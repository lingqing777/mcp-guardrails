# M-Bench-Core Dual-Layer Evaluation Report

**Dataset**: M-Bench-Core (MCP-native attack benchmark)
**Generated**: 2026-05-31 13:23:43
**Run git hash**: `unknown`
**Source**: `waf2\rag\eval\runs\2026-05-31-rq2-baselines-qwen2.5-1.5b-instruct\modsecurity-crs\cases-mbench-merged.jsonl`
**Total cases joined**: 300

**Layers evaluated**:
- `waf1_union` = WAF1 strict (`checkRules`) ∪ WAF1 full (`validateToolCall`)
- `rag_on` = WAF2 LLM analysis with RAG knowledge enhancement
- `dual` = `waf1_union` ∪ `rag_on`


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
| `WAF1 (strict ∪ full)` | 150 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
| `WAF2 + RAG (rag_on)` | 150 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
| `Dual (WAF1 ∪ WAF2)` | 150 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |

## Table 2 — Per-Family Confusion

Each family's confusion counts that family's attacks + ALL benigns (stable FPR denominator across families).

| family | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| Char injection | `WAF1 (strict ∪ full)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
| Prompt injection + privilege escalation | `WAF1 (strict ∪ full)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
| Call-chain composition | `WAF1 (strict ∪ full)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 50 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |

## Table 3 — Per-Tool-Universe (real vs synthetic)

Real tools: ['file_read_MCP', 'file_read_MCP_hacker', 'http-client', 'mail', 'server-github', 'supabase', 'woocommerce', 'wordpress']. Synthetic tools are any other `<server>` namespace (XML parsers, image processors, etc., introduced to cover attack categories absent from the real tool universe).

| universe | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| real | `WAF1 (strict ∪ full)` | 150 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 150 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 150 | 0 | 0 | 150 | 1.000 | 1.000 | 1.000 | 0.000 |
| synthetic | `WAF1 (strict ∪ full)` | 0 | 0 | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 0 | 0 | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 0 | 0 | 0 | 0 | 0.000 | 0.000 | 0.000 | 0.000 |

## Table 4 — Hard-neg vs Template FP Breakdown

Hard-neg benigns (`source="handcrafted"`) are paired with attacks and intentionally use attack-shaped parameters with business-normal semantics. Template benigns (`source="template"`) cover the stable business baseline.

| layer | handcrafted FP / total | template FP / total | Δpp (handcrafted − template) | overblock? |
|---|---|---|---|---|
| `WAF1 (strict ∪ full)` | 0 / 0 | 0 / 0 | +0.0 pp | no |
| `WAF2 + RAG (rag_on)` | 0 / 0 | 0 / 0 | +0.0 pp | no |
| `Dual (WAF1 ∪ WAF2)` | 0 / 0 | 0 / 0 | +0.0 pp | no |

## Table 5 — Chain Block-Step Distribution

Call-chain attacks grouped by `expected_block_step` (the latest step at which the system must block to count as TP).

_(no call_chain attacks present in the merged corpus)_

## Table 6 — Per-Subcategory Recall

Sorted by sample count desc.

| subcategory | n | waf1_union recall | rag_on recall | dual recall |
|---|---|---|---|---|
| `unknown` | 150 | 1.000 | 1.000 | 1.000 |

## Interpretation

- **Overall (N=300)**: dual F1 = 1.000, recall = 1.000, FPR = 0.000. WAF1-only F1 = 1.000, WAF2-only F1 = 1.000. Dual gain over WAF2 alone: ΔF1 = +0.000.
- **Char injection**: dual recall = 1.000 (TP=50/50). Best layer: `WAF1 (strict ∪ full)` at recall 1.000.
- **Prompt injection + privilege escalation**: dual recall = 1.000 (TP=50/50). Best layer: `WAF1 (strict ∪ full)` at recall 1.000.
- **Call-chain composition**: dual recall = 1.000 (TP=50/50). Best layer: `WAF1 (strict ∪ full)` at recall 1.000.
- **Real vs synthetic gap** (dual): real recall = 1.000, synthetic recall = 0.000 (Δ = +100.0 pp). Synthetic tools may not be well-targeted by current rules — consider this when reading aggregated metrics.

## Reproduction

```bash
# Re-run merge
PYTHONPATH=. python3 -m waf2.rag.scripts.merge_mbench_layers \
    --cases-dir <run-dir> \
    --dataset-dir waf2/rag/eval/m-bench-core/ \
    --out-dir <run-dir>

# Re-render this report
PYTHONPATH=. python3 -m waf2.rag.scripts.report_mbench \
    --merged waf2\rag\eval\runs\2026-05-31-rq2-baselines-qwen2.5-1.5b-instruct\modsecurity-crs\cases-mbench-merged.jsonl \
    --out <run-dir>/dual-layer-mbench-report.md
```

- Joined cases: 300
- Git hash: `unknown`
- Generated: 2026-05-31T13:23:43.134075
