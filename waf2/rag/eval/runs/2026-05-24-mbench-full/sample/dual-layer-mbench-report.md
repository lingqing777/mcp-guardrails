# M-Bench-Core Dual-Layer Evaluation Report

**Dataset**: M-Bench-Core (MCP-native attack benchmark)
**Generated**: 2026-05-24 19:32:21
**Run git hash**: `53688db`
**Source**: `waf2/rag/eval/runs/2026-05-24-mbench-full/sample/cases-mbench-merged.jsonl`
**Total cases joined**: 347 (= 150 attacks + 197 benign sample)

## Run Composition Disclosure

Benign 跑分采用了 **stratified sample 197 条**(而非完整 1000 条),用户决议(2026-05-24)以加快第一次 full-run 反馈速度,优先看 WAF 提升信号:

- **Hard-neg 段**: 127 条(每个 unique `(tool, args)` signature 各取 1 条 — 完全去重 hard-neg pool)
- **Template 段**: 70 条 stratified by tool namespace
  (woocommerce 359 → 28; wordpress 109 → 9; supabase 91 → 7; mail 48 → 4; file_read_MCP 34 → 3; http-client 59 → 5;
   保留至少 1 条 per ns;实际抽样后 woocommerce=78、wordpress=40、supabase=20、mail=26、file_read_MCP=10、http-client=19 — sample 中 hard-neg 占 64%,模拟"压力测试场景")
- **Attacks**: 完整 150 条全跑(无抽样)

**完整 1000 benign 的 WAF1 单层结果**已分开记录:
- WAF1 strict × 1000: 39 FP / 961 TN (FPR=3.9%)
- WAF1 full × 1000: 228 FP / 772 TN (FPR=22.8%)
(未参与本 merged 表,因为 WAF2 1000 条仅跑了 sample 197;若要把 WAF1 完整 1000 接入需要补 WAF2 完整 1000 的 rag-on 跑分,估计 5-7 小时)

后续 v2 full run 将跑完整 1000 benign × WAF2 rag-on + rag-off 双 round,产出"权威 FPR"数字。

**Layers evaluated**:
- `waf1_union` = WAF1 strict (`checkRules`) ∪ WAF1 full (`validateToolCall`)
- `rag_on` = WAF2 LLM analysis with RAG knowledge enhancement
- `dual` = `waf1_union` ∪ `rag_on`

**Note on `rag_off` layer**: 由 §10.1 用户决议,benign rag-off round 未跑(WAF2 LLM call 单 case ~22s,1000×2 round 估 11h+ 超出可接受时间)。Merge 阶段为 benign rag-off 生成 stub records(`outcome=passed`、`_stub=true` 标记),attacks rag-off 是真实跑分(36 min)。本报告里的 dual 层是 `waf1_union ∪ rag_on`,不依赖 rag_off,所以 stub 不影响主表数字;rag_off 仅出现在 merged JSONL 的诊断字段中,**不在本报告任何表中报告**。


## Fairness Disclosures

1. **M-Bench-Core has paired benigns by design.** F1 here uses real precision
   computed from TN/FP, not the precision=1 assumption used in B-0 evaluation.
   F1 = 2·precision·recall / (precision + recall).

2. **WAF2 cases for multi-step chains evaluate only the last step.** WAF2 is
   a stateless reverse proxy with no session awareness; cross-step reasoning is
   WAF1's domain via `CallChainTracker`. The `waf2_evaluated_step` column in
   merged JSONL records `len(steps)` for chain records, and Table 2's
   `call_chain` row for the `rag_on` layer reflects last-step-only intent.

3. **WAF1 strict on multi-step chains is "not applicable" by architecture.**
   `checkRules` cannot observe cross-step state. The harness emits a strict
   record per chain with `chain_strict_only=true` so case_id alignment is
   preserved, but its `blocked` flag captures only per-step rule hits, not
   chain detection. `waf1_union` correctly OR-aggregates strict + full.

4. **Real vs synthetic tool universe.** Synthetic tools (≤15% of cases) are
   reported separately in Table 3. If recall delta (real vs synthetic)
   exceeds 5 percentage points, the interpretation section discusses it.

5. **Paired hard-negatives shape FPR.** The 300 hand-crafted hard-neg benigns
   are intentionally adversarial (params look attack-like but semantics are
   business-normal). Table 4 reports hard-neg FP rate vs template FP rate
   separately so over-blocking is visible.

6. **RAG knowledge-base overlap.** The RAG knowledge base (`payloads.jsonl`,
   3364 entries from PayloadsAllTheThings + OWASP CRS) may share patterns
   with M-Bench-Core attacks. This is by design (RAG is meant to recognize
   known patterns) but high recall on attacks whose substrings appear in the
   KB should be read with awareness of this overlap.


## Table 1 — Overall Confusion

F1 uses **real precision** (M-Bench-Core has benigns; no precision=1 assumption).

| layer | TP | FN | FP | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| `WAF1 (strict ∪ full)` | 110 | 40 | 62 | 135 | 0.640 | 0.733 | 0.683 | 0.315 |
| `WAF2 + RAG (rag_on)` | 88 | 62 | 54 | 143 | 0.620 | 0.587 | 0.603 | 0.274 |
| `Dual (WAF1 ∪ WAF2)` | 125 | 25 | 81 | 116 | 0.607 | 0.833 | 0.702 | 0.411 |

## Table 2 — Per-Family Confusion

Each family's confusion counts that family's attacks + ALL benigns (stable FPR denominator across families).

| family | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| Char injection | `WAF1 (strict ∪ full)` | 43 | 7 | 62 | 135 | 0.410 | 0.860 | 0.555 | 0.315 |
|  | `WAF2 + RAG (rag_on)` | 46 | 4 | 54 | 143 | 0.460 | 0.920 | 0.613 | 0.274 |
|  | `Dual (WAF1 ∪ WAF2)` | 49 | 1 | 81 | 116 | 0.377 | 0.980 | 0.544 | 0.411 |
| Prompt injection + privilege escalation | `WAF1 (strict ∪ full)` | 31 | 19 | 62 | 135 | 0.333 | 0.620 | 0.434 | 0.315 |
|  | `WAF2 + RAG (rag_on)` | 31 | 19 | 54 | 143 | 0.365 | 0.620 | 0.459 | 0.274 |
|  | `Dual (WAF1 ∪ WAF2)` | 39 | 11 | 81 | 116 | 0.325 | 0.780 | 0.459 | 0.411 |
| Call-chain composition | `WAF1 (strict ∪ full)` | 36 | 14 | 62 | 135 | 0.367 | 0.720 | 0.486 | 0.315 |
|  | `WAF2 + RAG (rag_on)` | 11 | 39 | 54 | 143 | 0.169 | 0.220 | 0.191 | 0.274 |
|  | `Dual (WAF1 ∪ WAF2)` | 37 | 13 | 81 | 116 | 0.314 | 0.740 | 0.440 | 0.411 |

## Table 3 — Per-Tool-Universe (real vs synthetic)

Real tools: ['file_read_MCP', 'file_read_MCP_hacker', 'http-client', 'mail', 'server-github', 'supabase', 'woocommerce', 'wordpress']. Synthetic tools are any other `<server>` namespace (XML parsers, image processors, etc., introduced to cover attack categories absent from the real tool universe).

| universe | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| real | `WAF1 (strict ∪ full)` | 106 | 38 | 62 | 131 | 0.631 | 0.736 | 0.679 | 0.321 |
|  | `WAF2 + RAG (rag_on)` | 84 | 60 | 54 | 139 | 0.609 | 0.583 | 0.596 | 0.280 |
|  | `Dual (WAF1 ∪ WAF2)` | 121 | 23 | 81 | 112 | 0.599 | 0.840 | 0.699 | 0.420 |
| synthetic | `WAF1 (strict ∪ full)` | 4 | 2 | 0 | 4 | 1.000 | 0.667 | 0.800 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 4 | 2 | 0 | 4 | 1.000 | 0.667 | 0.800 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 4 | 2 | 0 | 4 | 1.000 | 0.667 | 0.800 | 0.000 |

## Table 4 — Hard-neg vs Template FP Breakdown

Hard-neg benigns (`source="handcrafted"`) are paired with attacks and intentionally use attack-shaped parameters with business-normal semantics. Template benigns (`source="template"`) cover the stable business baseline.

| layer | handcrafted FP / total | template FP / total | Δpp (handcrafted − template) | overblock? |
|---|---|---|---|---|
| `WAF1 (strict ∪ full)` | 51 / 127 (40.2%) | 11 / 70 (15.7%) | +24.4 pp | **⚠ OVERBLOCK** |
| `WAF2 + RAG (rag_on)` | 48 / 127 (37.8%) | 6 / 70 (8.6%) | +29.2 pp | **⚠ OVERBLOCK** |
| `Dual (WAF1 ∪ WAF2)` | 66 / 127 (52.0%) | 15 / 70 (21.4%) | +30.5 pp | **⚠ OVERBLOCK** |

> **⚠ Callout — Hard-neg overblock detected** on layer(s): `WAF1 (strict ∪ full)`, `WAF2 + RAG (rag_on)`, `Dual (WAF1 ∪ WAF2)`. Handcrafted FP rate exceeds template FP rate by ≥10 percentage points. This indicates the system is over-sensitive to attack-shaped benigns. Inspect the handcrafted samples (search for `source="handcrafted"` + `classification.<layer>="FP"` in the merged JSONL) to audit which patterns are tripping.

## Table 5 — Chain Block-Step Distribution

Call-chain attacks grouped by `expected_block_step` (the latest step at which the system must block to count as TP).

| expected_block_step | n | layer | TP | Recall |
|---|---|---|---|---|
| 1 | 14 | `WAF1 (strict ∪ full)` | 13 | 0.929 |
|  |  | `WAF2 + RAG (rag_on)` | 0 | 0.000 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 13 | 0.929 |
| 2 | 27 | `WAF1 (strict ∪ full)` | 18 | 0.667 |
|  |  | `WAF2 + RAG (rag_on)` | 9 | 0.333 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 19 | 0.704 |
| 3 | 9 | `WAF1 (strict ∪ full)` | 5 | 0.556 |
|  |  | `WAF2 + RAG (rag_on)` | 2 | 0.222 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 5 | 0.556 |

## Table 6 — Per-Subcategory Recall

Sorted by sample count desc.

| subcategory | n | waf1_union recall | rag_on recall | dual recall |
|---|---|---|---|---|
| `credential_theft` | 12 | 0.667 | 0.083 | 0.667 |
| `data_exfiltration` | 12 | 0.667 | 0.250 | 0.667 |
| `sql_injection` | 10 | 0.700 | 0.900 | 1.000 |
| `direct_pi` | 10 | 0.600 | 0.800 | 1.000 |
| `recon_then_exploit` | 10 | 0.700 | 0.500 | 0.800 |
| `xss` | 8 | 1.000 | 1.000 | 1.000 |
| `indirect_pi` | 8 | 0.875 | 0.875 | 0.875 |
| `jailbreak` | 8 | 1.000 | 1.000 | 1.000 |
| `tool_poisoning` | 8 | 0.875 | 0.375 | 0.875 |
| `supabase_lethal_trifecta` | 8 | 0.625 | 0.250 | 0.625 |
| `prompt_injection_to_exfil` | 8 | 1.000 | 0.000 | 1.000 |
| `prompt_leak` | 7 | 0.143 | 0.429 | 0.571 |
| `command_injection` | 6 | 1.000 | 1.000 | 1.000 |
| `path_traversal` | 6 | 0.500 | 1.000 | 1.000 |
| `ssrf` | 6 | 1.000 | 1.000 | 1.000 |
| `sensitive_files` | 5 | 0.800 | 0.400 | 0.800 |
| `dangerous_operations` | 5 | 1.000 | 1.000 | 1.000 |
| `rbac_bypass` | 5 | 0.200 | 0.200 | 0.200 |
| `xxe` | 4 | 1.000 | 1.000 | 1.000 |
| `scope_escalation` | 4 | 0.250 | 0.250 | 0.500 |

## Interpretation

- **Overall (N=347)**: dual F1 = 0.702, recall = 0.833, FPR = 0.411. WAF1-only F1 = 0.683, WAF2-only F1 = 0.603. Dual gain over WAF2 alone: ΔF1 = +0.100.
- **Char injection**: dual recall = 0.980 (TP=49/50). Best layer: `Dual (WAF1 ∪ WAF2)` at recall 0.980.
- **Prompt injection + privilege escalation**: dual recall = 0.780 (TP=39/50). Best layer: `Dual (WAF1 ∪ WAF2)` at recall 0.780.
- **Call-chain composition**: dual recall = 0.740 (TP=37/50). Best layer: `Dual (WAF1 ∪ WAF2)` at recall 0.740.
- **Real vs synthetic gap** (dual): real recall = 0.840, synthetic recall = 0.667 (Δ = +17.4 pp). Synthetic tools may not be well-targeted by current rules — consider this when reading aggregated metrics.
- **Chain block-step**: step-1 (early) dual recall = 0.929; step ≥2 (full-chain) average dual recall = 0.630. Chains that require seeing more steps are harder to catch.

## Reproduction

```bash
# Re-run merge
PYTHONPATH=. python3 -m waf2.rag.scripts.merge_mbench_layers \
    --cases-dir <run-dir> \
    --dataset-dir waf2/rag/eval/m-bench-core/ \
    --out-dir <run-dir>

# Re-render this report
PYTHONPATH=. python3 -m waf2.rag.scripts.report_mbench \
    --merged waf2/rag/eval/runs/2026-05-24-mbench-full/sample/cases-mbench-merged.jsonl \
    --out <run-dir>/dual-layer-mbench-report.md
```

- Joined cases: 347
- Git hash: `53688db`
- Generated: 2026-05-24T19:32:21.441044

## Run Wall-clock Timing

| Phase | n | Wall-clock | Mean / case |
|---|---|---|---|
| WAF1 strict + full × 150 attacks | 150 × 2 | < 1s | < 3ms |
| WAF1 strict + full × 1000 benigns | 1000 × 2 | ~4s | ~4ms |
| WAF1 strict + full × 197 sample (re-run for case_id alignment) | 197 × 2 | ~1s | ~5ms |
| **WAF2 rag-off × 150 attacks** | 150 | **33.4 min (2005s)** | **13.4s / case** |
| **WAF2 rag-on × 150 attacks** | 150 | **36.7 min (2199s)** | **14.7s / case** |
| **WAF2 rag-on × 197 benigns** | 197 | **67.4 min (4044s)** | **20.5s / case** |
| **WAF2 rag-off × 197 benigns** | 197 | **0s (stub: 用户决议跳过)** | n/a |
| **TOTAL WAF2 LLM-bound time** | 547 LLM calls | **2.3 hours** | **15.2s / call avg** |
| **TOTAL run-end-to-end (含 WAF1, harness overhead)** | 1497 total invocations | **~2.4 hours** | n/a |

### Latency Distribution

```
attacks rag-off (n=150): mean=13367ms median=21600ms p95=24216ms max=26697ms
attacks rag-on  (n=150): mean=14664ms median=22533ms p95=26160ms max=28910ms
benigns rag-on  (n=197): mean=~20500ms (computed from total wall-clock)
```

Bimodal latency 分布:
- 一小部分 (≈ 25%) 走 WAF2 静态规则 fast block / fast pass(< 100ms)
- 大部分 (≈ 75%) 走 LLM Agent + RAG 完整路径(18–28s)

### LLM 上游
- Model: `qwen3:8b` via Ollama at `http://host.docker.internal:11434/v1`
- LLM timeout: 180s, fail policy: `fail_open`
- RAG knowledge base: 3364 entries (PayloadsAllTheThings + OWASP CRS)
- Hardware: WSL2 单 GPU (sequential LLM serving)

### WAF1 wall-clock 几乎可忽略(< 5s 累计),M-Bench-Core 的真实评测时间瓶颈在 WAF2 的 LLM 调用串行。
