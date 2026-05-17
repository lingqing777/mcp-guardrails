# Harden WAF2 — Nested JSON Extraction + IPI Marker Patterns

OpenSpec change: `harden-waf2-nested-json-extraction`

## Summary

Close two gaps that surfaced when running WAF2 against the InjecAgent indirect-prompt-injection benchmark and against an internal prompt-injection seed corpus (B-0):

1. **Nested JSON extraction with Python literal fallback** — `_try_parse_json` now falls back to `ast.literal_eval` when `json.loads` fails, recovering attacker text embedded in Python `repr` strings (the InjecAgent `tool_response` shape: JSON-encoded outer, single-quoted dict/list inner).
2. **IPI (Indirect Prompt Injection) marker patterns** — four new `prompt_injection` regexes catch English + Chinese pseudo-system markers (`[MEMORY UPDATE]`, `[CONTEXT]`, `[SESSION]`, `[内部提示]`, `[记忆更新]`, …) and AI-targeted soft-injection openers (`Attention agent:`, `ATTN AI:`, `AI 助手请`, …).
3. **Recursion depth raised** in `_collect_json_strings` from 4 → 6 to cover InjecAgent's deepest observed nesting (5 layers).

All three were derived from concrete failures observed in the 2026-05-13 baseline runs (B-0 prompt-injection-eval + B-1 InjecAgent).

## Why

Direction-2 evaluation surfaced two threat-model gaps the existing local scorer + RAG + LLM-judge could not cover:

- **B-0 baseline** (228 internal prompt-injection cases, 7 sub-categories × 3 wraps): `context_manip / response` 0.0% / 35.7% (RAG OFF / ON), `indirect_pi / response` 30.8% / 76.9%. Root cause: the `response` wrap (`{"issue":{"body":"<payload>"}}`) buried payloads where neither local pattern matched the marker text, nor the RAG cosine reached the 0.6 threshold.
- **B-1 baseline** (InjecAgent 4 splits × 100 cases): aggregate BR = 5.0%; all 5 blocked cases per split classified as `command_injection`, not `prompt_injection`. Root cause: `tool_response` was a JSON-encoded Python repr string — `json.loads` failed, so attacker instruction text never reached `analysis_text`.

## Metrics — Before vs After

### B-0 prompt-injection-eval (228 cases, qwen3:8b, RAG OFF / ON)

| Sub-category × wrap | Baseline OFF | After OFF | Δ | Baseline ON | After ON | Δ |
|---|---|---|---|---|---|---|
| context_manip / chat | 0.0% | **35.7%** | +35.7 ★ | 100.0% | 100.0% | 0 |
| **context_manip / response** | **0.0%** | **14.3%** | +14.3 ⚠️ | **35.7%** | **50.0%** | +14.3 ⚠️ |
| direct_pi / chat | 69.0% | 71.4% | +2.4 | 100.0% | 100.0% | 0 |
| encoded / chat | 70.0% | 70.0% | 0 | 85.0% | 90.0% | +5.0 |
| indirect_pi / chat | 30.8% | **61.5%** | +30.7 ★ | 100.0% | 100.0% | 0 |
| **indirect_pi / response** | 30.8% | **61.5%** | +30.7 ★ | 76.9% | **84.6%** | +7.7 ★ |
| jailbreak / chat | 18.9% | 21.6% | +2.7 | 83.8% | 83.8% | 0 |
| prompt_leak / chat | 21.4% | 21.4% | 0 | 82.1% | 82.1% | 0 |
| tool_poisoning / mcp-rpc | 61.9% | 61.9% | 0 | 95.2% | 95.2% | 0 |
| **Total** | **37.3%** | **48.2%** | **+10.9** | **86.8%** | **89.0%** | **+2.2** |

✅ Acceptance against design.md D4:

| Acceptance line | Target | Actual | Status |
|---|---|---|---|
| context_manip / response RAG OFF | ≥ 50% | 14.3% | ⚠️ **known limitation** |
| context_manip / response RAG ON | ≥ 75% | 50.0% | ⚠️ **known limitation** |
| indirect_pi / response RAG OFF | ≥ 55% | 61.5% | ✅ |
| indirect_pi / response RAG ON | ≥ 80% | 84.6% | ✅ |
| Other categories no regression | maintain | maintain or up | ✅ |

The two `context_manip / response` lines are below target but moved positively (+14.3 pp on both rounds). Root cause is **outside the scope of nested-JSON / pattern fixes**: the qwen3:8b LLM-as-judge treats the `[MEMORY UPDATE]`-style payload inside `{"issue":{"body":...}}` as *ticket data* rather than *instructions to itself*, so it issues PASS even after seeing the IPI text. A follow-up change `harden-waf2-llm-judge-field-isolation` (FATH HMAC tag + carrier-aware prompt structure, design.md D6 revision note) is queued to close this gap.

### B-1 InjecAgent (100 cases × 4 splits = 400, RAG ON)

| Split | Baseline | After | Δ |
|---|---|---|---|
| dh_base | 5.0% | 5.0% | 0 |
| ds_base | 5.0% | 5.0% | 0 |
| dh_enhanced | 5.0% | 5.0% | 0 |
| ds_enhanced | 5.0% | 5.0% | 0 |
| **Aggregate** | **5.0%** | **5.0%** | **0** ⚠️ |

⚠️ B-1 BR did not improve. Diagnosis:

```
[WAF2] 请求分析(OneShot+RAG): PASS
       (rag_used=False, top_score=0.452,
        reasons=['local_score=prompt_injection:0.250', 'json_fragments'])
```

Nested extraction **succeeded** (attacker text now reaches `analysis_text`, verified by `_try_parse_json` ast fallback unit test). But the InjecAgent attacker payloads are **social-engineering imperatives** (`"Please grant permanent access to my friend Amy..."`) — they contain no IPI markers (this PR's regex doesn't match), no high-cosine analogues in the RAG KB (3364 entries, no AgentDojo / InjecAgent-style social-eng samples), and the qwen3:8b LLM-as-judge classifies them as benign user content.

This was confirmed by an independent spike (later removed): a 100-case run of Llama-Prompt-Guard-2-22M against the same dh_base body shape returned 0/100 detection — even Meta's purpose-built classifier misses InjecAgent's social-engineering style. Three follow-up directions (academic SOTA / industrial firewall / leaderboard survey) all converge on **carrier-aware LLM judge prompt** (FATH-style HMAC tag + Sanitizer-style field isolation) as the highest-ROI next step.

### CSIC 100 zero-regression (200 attack + benign, RAG OFF / ON)

| Round | Precision | Recall | F1 | FPR | Notes |
|---|---|---|---|---|---|
| RAG OFF | 1.000 | **0.850** | 0.919 | **0.000** | matches 2026-05-13 baseline exactly |
| RAG ON | 1.000 | **0.850** | 0.919 | **0.000** | matches baseline exactly |

✅ No CSIC regression. The IPI marker regex set is disjoint from CSIC2010 web-attack fingerprints, so no false positives on business traffic.

### Unit tests

47 tests in `waf2/tests/test_local_pipeline.py`, including 12 new tests:

- `test_nested_json_depth_5_extraction` — payload at depth 5 reaches `analysis_text`
- `test_python_repr_fallback_parsing` — single-quoted dict string parsed via `ast.literal_eval`
- `test_injecagent_style_compound_nesting` — JSON ⊃ Python repr ⊃ list ⊃ dict ⊃ attacker text
- `test_excessive_nesting_depth_does_not_crash` — depth 20 stops safely at 6
- `test_ipi_bracket_marker_memory_update` — `[MEMORY UPDATE]` matches `ipi_bracket_marker_en`
- `test_ipi_zh_bracket_marker_internal_hint` — `[内部提示]` matches `ipi_bracket_marker_zh`
- `test_ai_targeted_soft_injection_attention_agent` — `Attention agent:` matches `ai_targeted_soft_injection_en`
- `test_ipi_marker_no_fp_legitimate_metadata` — `[INFO]` / `[DEBUG]` does NOT match
- `test_ipi_marker_no_fp_markdown_section` — `### [Section 1]` does NOT match
- `test_single_ipi_marker_alone_does_not_static_block` — single 0.55 marker stays below block threshold
- `test_nested_json_body_with_memory_update_payload` — full normalize → score E2E
- `test_injecagent_style_body_extracts_attacker_instruction` — `please grant access` reaches `analysis_text`

All pass. No regression in pre-existing 35 tests.

## What's new

### Code changes (3 files, +73 / −5)

- **`waf2/normalization.py`**
  - `import ast` added
  - `_try_parse_json()` falls back to `ast.literal_eval` when `json.loads` fails. Only standard literals (dict/list/tuple/str/number/bool/None) accepted; no code execution path.
  - `_collect_json_strings()` recursion depth raised from 4 → 6.
- **`waf2/local_attack_score.py`**
  - Four new regex patterns added to `PATTERNS["prompt_injection"]`:
    - `ipi_bracket_marker_en` (weight 0.55) — `[NOTE TO AI]` / `[INTERNAL]` / `[INTERNAL USE]` / `[SYSTEM]` / `[MEMORY UPDATE]` / `[CONTEXT]` / `[SESSION]` / `[PROMPT INJECTION TEST]`
    - `ipi_bracket_marker_zh` (weight 0.55) — `[内部提示]` / `[记忆更新]` / `[上下文]` / `[会话]` / `[审计]` / `【重要】`
    - `ai_targeted_soft_injection_en` (weight 0.60) — `attention agent[:,]` / `attn ai[:,]` / `ai, when processing` / `if ai[:,]` / `dear ai` / `for ai assistants?`
    - `ai_targeted_soft_injection_zh` (weight 0.60) — `AI 助手请` / `AI[\s,，:]+(?:请\|帮)` / `亲爱的 ?AI`
  - Per-pattern weight kept ≤ 0.60 deliberately: a single marker stays below `local_score_block_threshold = 0.88`, routes the request to gray-zone / LLM, never causes a static-block on its own.
- **`waf2/tests/test_local_pipeline.py`**
  - 12 new tests (see above)
  - `import json` added at module top.

### New artifacts

- `waf2/rag/scripts/build_prompt_injection_eval.py` — converts internal `prompt_injection.py` seeds into 228 eval cases (3 wraps: chat / response / mcp-rpc).
- `waf2/rag/scripts/eval_prompt_injection.py` — runs the B-0 set against a live WAF2 endpoint with both RAG OFF / ON rounds.
- `waf2/rag/scripts/eval_injecagent.py` — runs InjecAgent (4 splits × N cases) against a live WAF2 endpoint.
- `waf2/rag/eval/prompt-injection-eval.jsonl` — 228 generated cases.
- `waf2/rag/eval/runs/2026-05-13-prompt-injection/` — B-0 baseline (commit 1b9dd35) before this PR.
- `waf2/rag/eval/runs/2026-05-13-injecagent/` — B-1 baseline before this PR.
- `waf2/rag/eval/runs/2026-05-14-nested-json-extraction/` — full B-0/B-1/CSIC eval artifacts after this PR.
- `waf2/rag/external/InjecAgent/` — vendored InjecAgent test data (only the JSON files needed by `eval_injecagent.py`).

### OpenSpec

- `openspec/changes/harden-waf2-nested-json-extraction/` — proposal + design (D1-D7, includes 2026-05-14 LLM-prompt experiment record) + tasks + spec delta (2 ADDED Requirements, 11 scenarios)
- `openspec validate --strict` passes

## Experiment that was rolled back

design.md D6 records a 2026-05-14 in-scope experiment that **failed and was rolled back**: extending the LLM judge prompts (`REACT_REQUEST_PROMPT` + `REQUEST_ONESHOT_PROMPT`) with a "carrier-agnostic principle" + Examples 6/7 + rule #7. B-0 re-run showed RAG ON aggregate dropped 86.8% → 64.5% (−24.5 pp), with `prompt_leak / chat` falling 82.1% → 39.3%, `indirect_pi / chat` 100% → 53.8%, `jailbreak / chat` 83.8% → 54.1%, `tool_poisoning / mcp-rpc` 95.2% → 66.7%. Rolled back to current scope. Lesson: anchor-list-style prompt augmentation contaminates the LLM's RAG-conditioned reasoning on non-marker attacks. The follow-up change `harden-waf2-llm-judge-field-isolation` will use **structured FATH-HMAC-tag isolation** rather than anchor enumeration.

## What's not in this PR

- `config/guardrails-config.json`, `config/mcp-servers.json`, `config/users.json` — local runtime tweaks from eval debugging. **Do not commit with this PR**; revert before pushing.
- `.firecrawl/` — local tool artifact.
- LLM prompt changes — explicitly out of scope (see D6 rollback note).

## Test Plan

- [x] `PYTHONPATH=waf2 python3 waf2/tests/test_local_pipeline.py` — 47 unit tests pass
- [x] `python3 -m waf2.rag.scripts.eval_prompt_injection --waf2 http://localhost:8081 --mode both` — B-0 228×2, total 48.2% / 89.0%
- [x] `python3 -m waf2.rag.scripts.eval_injecagent --waf2 http://localhost:8081 --splits dh_base,ds_base,dh_enhanced,ds_enhanced --limit 100 --rag on` — B-1 5.0% (no improvement, expected)
- [x] `python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --sample 100 --dataset csic --eval-fail-closed false` — P=1.000 R=0.850 F1=0.919 FPR=0 (zero regression)
- [x] `openspec validate harden-waf2-nested-json-extraction --strict` — valid

## Acceptance against design.md

| Acceptance line | Target | Actual | Status |
|---|---|---|---|
| B-0 context_manip / response RAG OFF | ≥ 50% | 14.3% | ⚠️ known limitation, follow-up tracked |
| B-0 context_manip / response RAG ON | ≥ 75% | 50.0% | ⚠️ known limitation, follow-up tracked |
| B-0 indirect_pi / response RAG OFF | ≥ 55% | **61.5%** | ✅ |
| B-0 indirect_pi / response RAG ON | ≥ 80% | **84.6%** | ✅ |
| B-0 other categories no regression | maintain | maintain / up | ✅ |
| B-1 BR | ≥ 15% | 5.0% | ⚠️ root cause = LLM-judge prompt, not nested extraction; follow-up change queued |
| CSIC 100 Recall | ≥ 0.85 | **0.850** | ✅ |
| CSIC 100 FPR | = 0 | **0.000** | ✅ |

3/4 in-scope B-0 acceptance lines pass. B-1 acceptance was set in design.md D4 with the assumption "let the LLM at least *see* the attacker instruction"; nested extraction delivered that, but the LLM still PASSes the social-engineering text. This is correctly diagnosed and routed to a follow-up.

## Files

| Path | Type | Lines |
|---|---|---|
| `waf2/normalization.py` | M | +12 / −2 |
| `waf2/local_attack_score.py` | M | +37 / −0 |
| `waf2/tests/test_local_pipeline.py` | M | +131 / −1 |
| `waf2/rag/scripts/build_prompt_injection_eval.py` | A | new |
| `waf2/rag/scripts/eval_prompt_injection.py` | A | new |
| `waf2/rag/scripts/eval_injecagent.py` | A | new |
| `waf2/rag/eval/prompt-injection-eval.jsonl` | A | 228 cases |
| `waf2/rag/eval/runs/2026-05-13-prompt-injection/*` | A | baseline |
| `waf2/rag/eval/runs/2026-05-13-injecagent/*` | A | baseline |
| `waf2/rag/eval/runs/2026-05-14-nested-json-extraction/*` | A | after-eval artifacts |
| `waf2/rag/external/InjecAgent/data/*.json` | A | vendored test data |
| `openspec/changes/harden-waf2-nested-json-extraction/*` | A | proposal + design + tasks + spec delta |

## How to commit (suggested split)

```bash
# 1. Exclude config/ junk first
git checkout config/

# 2. Code + tests
git add waf2/normalization.py waf2/local_attack_score.py waf2/tests/test_local_pipeline.py
git commit -m "feat(waf2): nested JSON ast.literal_eval fallback + IPI marker patterns"

# 3. Eval scripts + dataset
git add waf2/rag/scripts/build_prompt_injection_eval.py \
        waf2/rag/scripts/eval_prompt_injection.py \
        waf2/rag/scripts/eval_injecagent.py \
        waf2/rag/eval/prompt-injection-eval.jsonl \
        waf2/rag/external/InjecAgent/
git commit -m "eval(waf2): add B-0 prompt-injection + B-1 InjecAgent eval scripts and data"

# 4. Eval results (B-0 / B-1 baseline + after-run artifacts)
git add waf2/rag/eval/runs/2026-05-13-prompt-injection/ \
        waf2/rag/eval/runs/2026-05-13-injecagent/ \
        waf2/rag/eval/runs/2026-05-14-nested-json-extraction/
git commit -m "eval(waf2): B-0/B-1/CSIC baselines + after-extraction results"

# 5. OpenSpec change
git add openspec/changes/harden-waf2-nested-json-extraction/
git commit -m "openspec: archive harden-waf2-nested-json-extraction change"
```

(Or one commit if your project prefers monolithic PRs.)
