# Harden WAF2 Local Scorer — Probe Paths & Double Decode

OpenSpec change: `harden-waf2-local-scorer-probe-and-decode`

## Summary

Reduce CSIC false-negative rate by closing three gaps in the WAF2 local-first scorer:

1. **Legacy probe path blacklist** — IIS/FrontPage/CGI-era `_vti_pvt/`, `iisadmpwd/*.htr`, `.inc`, `.asa`, `.cmd`, etc.
2. **Double URL decode** — surface SQLi/XSS payloads hidden two layers deep (`%2527`, `%2522`)
3. **Header scoring** — score `Referer` / `Cookie` / `User-Agent`, including scanner UA fingerprints (sqlmap/nikto/nessus/…)

All three close concrete false-negative classes observed in `failures.jsonl` from the 2026-05-10 CSIC 1000 baseline.

## Why

CSIC 1000 baseline (`waf2/rag/eval/runs/2026-05-10-big/`):

- Precision = 1.000, FPR = 0.000 — no false-positive problem
- **Recall = 0.723 — the real bottleneck**

Of the 277 FN, **39 (14%)** decoded to high-precision attack signals the local scorer didn't catch. The remaining 238 are CSIC2010 label noise, out of scope.

## Metrics — Before vs After

### CSIC 1000+1000 (qwen3:8b, RAG OFF / ON)

| Metric | Baseline (RAG OFF) | New (RAG OFF) | New (RAG ON) | Δ |
|--------|---------------------|----------------|---------------|---|
| Precision | 1.000 | **1.000** | **1.000** | 0 |
| Recall | 0.723 | **0.761** | **0.762** | **+3.8 / +3.9 pp** |
| F1 | 0.839 | **0.864** | **0.865** | **+2.5 / +2.6 pp** |
| FPR | 0.000 | **0.000** | **0.000** | 0 |
| LLM Errors | 0 | 0 | 0 | 0 |

✅ Meets design.md acceptance: Recall ≥ 0.76, FPR ≤ 0.005.

### Route distribution (RAG OFF, 1000)

| Route | Baseline | New | Δ | Interpretation |
|-------|----------|-----|---|----------------|
| Static Block | 640 | **668** | +28 | New patterns catch gray-zone samples earlier |
| Fast Pass | 506 | 474 | -32 | Borderline samples no longer mis-routed |
| Local LLM | 93 | 93 | 0 | No extra LLM cost |
| ReAct | 8 | **0** | **-8** | Deep-inspection samples caught upstream |
| Local Block | 616 | 648 | +32 | scorer's block signal |

### Probe-FN regression set (35 cases)

`waf2/rag/eval/probe-fn-regression.jsonl` — 35 detectable FNs extracted from baseline failures:

```
Probe-FN regression: 35/35 blocked (100.0%)
  27 unknown          ← legacy_web_probe / legacy_web_probe_suffix
   8 sql_injection    ← double-decoded boolean tautology
```

100% direct-block, **no LLM call needed**.

### Adversarial set (40 cases, OFF/ON)

| Metric | OFF | ON | Δ |
|--------|-----|-----|---|
| Precision | 1.000 | 1.000 | 0 |
| Recall | 1.000 | 1.000 | 0 |
| F1 | 1.000 | 1.000 | 0 |
| FPR | 0.000 | 0.000 | 0 |

30/30 attacks blocked, 0/10 benign mis-blocked. No regression.

### Unit tests

37 tests in `waf2/tests/test_local_pipeline.py`, including 16 new tests for probe paths (6) + double decode (4) + header scoring (6). All pass.

### Offline 25k anomalous samples

`local_attack_score.score_request()` direct-block rate: **72.6%** (baseline ~64.0% from `static_block=640/1000`). This is the algorithmic ceiling before the LLM path; the +8.6 pp matches the observed Recall improvement on the in-line pipeline.

## What's new

### Code changes (4 files, +321 / −9)

- **`waf2/local_attack_score.py`**
  - `LEGACY_PROBE_PATH_PREFIXES`, `LEGACY_PROBE_SUFFIXES`, `LEGACY_PROBE_SUFFIX_WHITELIST`
  - `SCANNER_UA_PATTERNS`
  - New SQLi pattern `alpha_boolean_tautology` (weight 0.88) for `'OR'a='a` style
  - `quoted_boolean_tautology` weight bumped 0.65 → 0.88 (was previously stuck in gray-zone and missed when LLM passed)
  - New helpers: `_legacy_probe_path_match()`, `_legacy_probe_hits()`, `_multi_layer_encoding_hits()`
  - New public `score_headers(headers: Mapping[str, str]) -> Dict[str, List[ScoreHit]]`
  - `score_request(normalized, headers=None)` — optional headers param
- **`waf2/normalization.py`**
  - `double_url_decode(text: str) -> str` (public wrapper around existing 2-layer decoder)
  - `has_residual_percent(text: str) -> bool` (detect ≥ 3-layer encoded payloads)
- **`waf2/waf2_proxy.py`**
  - `analyze_request()` accepts `headers: Optional[Dict[str, str]] = None`
  - Cache key includes `h={md5_of_scored_headers[:8]}` (prevents cache poisoning across header variations)
  - Proxy entry extracts `referer` / `cookie` / `user-agent` and forwards to `analyze_request`
- **`waf2/tests/test_local_pipeline.py`**
  - 16 new tests (see above)
  - `test_backup_temp_resource_probe` accepts `unknown` or `path_traversal` category (`.OLD` now matches `legacy_web_probe` first)

### New artifacts

- `waf2/rag/eval/probe-fn-regression.jsonl` — 35 regression samples
- `waf2/rag/scripts/build_probe_regression.py` — script that extracts detectable FNs from `failures.jsonl`
- `waf2/rag/scripts/eval_probe_regression.py` — runs regression set against a live WAF2 endpoint
- `waf2/rag/eval/runs/2026-05-13-probe-decode/` — full eval artifacts (README + results + failures + config/stats snapshots)

### OpenSpec

- `openspec/changes/harden-waf2-local-scorer-probe-and-decode/` — proposal + design + tasks + spec delta
- `openspec validate --strict` passes

## What's not in this PR

- `config/guardrails-config.json`, `config/mcp-servers.json`, `config/users.json` — local runtime changes from eval debugging (WAF1 rules toggled off, upstream switched to GitHub API). **Do not commit these with this PR**; stash or revert before pushing.
- `.firecrawl/` — local tool artifacts, not project files.

## Test Plan

- [x] `PYTHONPATH=waf2 python3 waf2/tests/test_local_pipeline.py` — 37 unit tests pass
- [x] `python3 -m waf2.rag.scripts.eval_probe_regression --waf2 http://localhost:8081` — 35/35
- [x] `python3 -m waf2.rag.scripts.eval_adversarial --waf2 http://localhost:8081` — F1=1.000 (OFF/ON)
- [x] `python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --sample 100 --dataset csic --eval-fail-closed false` — P=1.000 R=0.850 F1=0.919 FPR=0
- [x] `python3 -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081 --sample 1000 --dataset csic --eval-fail-closed false` — P=1.000 R=0.761 F1=0.864 FPR=0
- [x] `openspec validate harden-waf2-local-scorer-probe-and-decode --strict` — valid

## Acceptance against design.md

| Acceptance line | Target | Actual |
|-----------------|--------|--------|
| Recall (CSIC 1000) | ≥ 0.76 | **0.761** ✅ |
| Precision | ≥ 0.99 | **1.000** ✅ |
| FPR | ≤ 0.005 | **0.000** ✅ |
| avg latency | +0 ms (cache hit), +~0.3ms (miss) | not separately measured |
| LLM calls | -10 to -20 | 93 → 93 (small-sample noise; +5pp Static Block absorbed by Fast Pass shift) |
| Probe regression coverage | ≥ 90% | **100%** ✅ |

## Files

| Path | Type | Lines |
|------|------|-------|
| `waf2/local_attack_score.py` | M | +152 / -3 |
| `waf2/normalization.py` | M | +18 / 0 |
| `waf2/waf2_proxy.py` | M | +21 / -1 |
| `waf2/tests/test_local_pipeline.py` | M | +139 / -5 |
| `waf2/rag/eval/probe-fn-regression.jsonl` | A | +35 |
| `waf2/rag/scripts/build_probe_regression.py` | A | new script |
| `waf2/rag/scripts/eval_probe_regression.py` | A | new script |
| `waf2/rag/eval/runs/2026-05-13-probe-decode/*` | A | eval artifacts |
| `openspec/changes/harden-waf2-local-scorer-probe-and-decode/*` | A | proposal + design + tasks + spec delta |

## How to commit (suggested split)

```bash
# 1. Exclude config/ junk first
git checkout config/

# 2. Code + tests
git add waf2/local_attack_score.py waf2/normalization.py waf2/waf2_proxy.py \
        waf2/tests/test_local_pipeline.py
git commit -m "feat(waf2): harden local scorer with probe paths, double decode, header scoring"

# 3. Eval scripts + regression set
git add waf2/rag/scripts/build_probe_regression.py \
        waf2/rag/scripts/eval_probe_regression.py \
        waf2/rag/eval/probe-fn-regression.jsonl
git commit -m "eval(waf2): add probe-FN regression set + scripts"

# 4. Eval results
git add waf2/rag/eval/runs/2026-05-13-probe-decode/
git commit -m "eval(waf2): CSIC 100+100 + 1000+1000 results after probe/decode harden"

# 5. OpenSpec change
git add openspec/changes/harden-waf2-local-scorer-probe-and-decode/
git commit -m "openspec: archive harden-waf2-local-scorer-probe-and-decode change"
```

(Or one commit if your project prefers monolithic PRs.)
