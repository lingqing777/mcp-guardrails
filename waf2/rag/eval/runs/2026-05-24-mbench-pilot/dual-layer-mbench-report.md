# M-Bench-Core Dual-Layer Evaluation Report

**Dataset**: M-Bench-Core (MCP-native attack benchmark)
**Generated**: 2026-05-24 13:05:13
**Run git hash**: `53688db`
**Source**: `waf2/rag/eval/runs/2026-05-24-mbench-pilot/cases-mbench-merged.jsonl`
**Total cases joined**: 50

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
| `WAF1 (strict ∪ full)` | 37 | 8 | 4 | 1 | 0.902 | 0.822 | 0.860 | 0.800 |
| `WAF2 + RAG (rag_on)` | 32 | 13 | 2 | 3 | 0.941 | 0.711 | 0.810 | 0.400 |
| `Dual (WAF1 ∪ WAF2)` | 40 | 5 | 4 | 1 | 0.909 | 0.889 | 0.899 | 0.800 |

## Table 2 — Per-Family Confusion

Each family's confusion counts that family's attacks + ALL benigns (stable FPR denominator across families).

| family | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| Char injection | `WAF1 (strict ∪ full)` | 15 | 0 | 4 | 1 | 0.789 | 1.000 | 0.882 | 0.800 |
|  | `WAF2 + RAG (rag_on)` | 15 | 0 | 2 | 3 | 0.882 | 1.000 | 0.938 | 0.400 |
|  | `Dual (WAF1 ∪ WAF2)` | 15 | 0 | 4 | 1 | 0.789 | 1.000 | 0.882 | 0.800 |
| Prompt injection + privilege escalation | `WAF1 (strict ∪ full)` | 11 | 4 | 4 | 1 | 0.733 | 0.733 | 0.733 | 0.800 |
|  | `WAF2 + RAG (rag_on)` | 12 | 3 | 2 | 3 | 0.857 | 0.800 | 0.828 | 0.400 |
|  | `Dual (WAF1 ∪ WAF2)` | 13 | 2 | 4 | 1 | 0.765 | 0.867 | 0.812 | 0.800 |
| Call-chain composition | `WAF1 (strict ∪ full)` | 11 | 4 | 4 | 1 | 0.733 | 0.733 | 0.733 | 0.800 |
|  | `WAF2 + RAG (rag_on)` | 5 | 10 | 2 | 3 | 0.714 | 0.333 | 0.455 | 0.400 |
|  | `Dual (WAF1 ∪ WAF2)` | 12 | 3 | 4 | 1 | 0.750 | 0.800 | 0.774 | 0.800 |

## Table 3 — Per-Tool-Universe (real vs synthetic)

Real tools: ['file_read_MCP', 'file_read_MCP_hacker', 'http-client', 'mail', 'server-github', 'supabase', 'woocommerce', 'wordpress']. Synthetic tools are any other `<server>` namespace (XML parsers, image processors, etc., introduced to cover attack categories absent from the real tool universe).

| universe | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| real | `WAF1 (strict ∪ full)` | 35 | 7 | 4 | 1 | 0.897 | 0.833 | 0.864 | 0.800 |
|  | `WAF2 + RAG (rag_on)` | 29 | 13 | 2 | 3 | 0.935 | 0.690 | 0.795 | 0.400 |
|  | `Dual (WAF1 ∪ WAF2)` | 37 | 5 | 4 | 1 | 0.902 | 0.881 | 0.892 | 0.800 |
| synthetic | `WAF1 (strict ∪ full)` | 2 | 1 | 0 | 0 | 1.000 | 0.667 | 0.800 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 3 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 3 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 0.000 |

## Table 4 — Hard-neg vs Template FP Breakdown

Hard-neg benigns (`source="handcrafted"`) are paired with attacks and intentionally use attack-shaped parameters with business-normal semantics. Template benigns (`source="template"`) cover the stable business baseline.

| layer | handcrafted FP / total | template FP / total | Δpp (handcrafted − template) | overblock? |
|---|---|---|---|---|
| `WAF1 (strict ∪ full)` | 4 / 5 (80.0%) | 0 / 0 | +80.0 pp | **⚠ OVERBLOCK** |
| `WAF2 + RAG (rag_on)` | 2 / 5 (40.0%) | 0 / 0 | +40.0 pp | **⚠ OVERBLOCK** |
| `Dual (WAF1 ∪ WAF2)` | 4 / 5 (80.0%) | 0 / 0 | +80.0 pp | **⚠ OVERBLOCK** |

> **⚠ Callout — Hard-neg overblock detected** on layer(s): `WAF1 (strict ∪ full)`, `WAF2 + RAG (rag_on)`, `Dual (WAF1 ∪ WAF2)`. Handcrafted FP rate exceeds template FP rate by ≥10 percentage points. This indicates the system is over-sensitive to attack-shaped benigns. Inspect the handcrafted samples (search for `source="handcrafted"` + `classification.<layer>="FP"` in the merged JSONL) to audit which patterns are tripping.

## Table 5 — Chain Block-Step Distribution

Call-chain attacks grouped by `expected_block_step` (the latest step at which the system must block to count as TP).

| expected_block_step | n | layer | TP | Recall |
|---|---|---|---|---|
| 1 | 3 | `WAF1 (strict ∪ full)` | 3 | 1.000 |
|  |  | `WAF2 + RAG (rag_on)` | 0 | 0.000 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 3 | 1.000 |
| 2 | 10 | `WAF1 (strict ∪ full)` | 7 | 0.700 |
|  |  | `WAF2 + RAG (rag_on)` | 4 | 0.400 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 8 | 0.800 |
| 3 | 2 | `WAF1 (strict ∪ full)` | 1 | 0.500 |
|  |  | `WAF2 + RAG (rag_on)` | 1 | 0.500 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 1 | 0.500 |

## Table 6 — Per-Subcategory Recall

Sorted by sample count desc.

| subcategory | n | waf1_union recall | rag_on recall | dual recall |
|---|---|---|---|---|
| `credential_theft` | 4 | 0.750 | 0.000 | 0.750 |
| `data_exfiltration` | 4 | 0.750 | 0.500 | 1.000 |
| `sql_injection` | 3 | 1.000 | 1.000 | 1.000 |
| `direct_pi` | 3 | 1.000 | 1.000 | 1.000 |
| `jailbreak` | 3 | 1.000 | 1.000 | 1.000 |
| `tool_poisoning` | 3 | 1.000 | 0.667 | 1.000 |
| `recon_then_exploit` | 3 | 0.667 | 0.667 | 0.667 |
| `xss` | 2 | 1.000 | 1.000 | 1.000 |
| `command_injection` | 2 | 1.000 | 1.000 | 1.000 |
| `path_traversal` | 2 | 1.000 | 1.000 | 1.000 |
| `ssrf` | 2 | 1.000 | 1.000 | 1.000 |
| `xxe` | 2 | 1.000 | 1.000 | 1.000 |
| `indirect_pi` | 2 | 1.000 | 1.000 | 1.000 |
| `prompt_leak` | 2 | 0.000 | 0.500 | 0.500 |
| `supabase_lethal_trifecta` | 2 | 0.500 | 0.500 | 0.500 |
| `prompt_injection_to_exfil` | 2 | 1.000 | 0.000 | 1.000 |
| `sensitive_files` | 1 | 1.000 | 1.000 | 1.000 |
| `dangerous_operations` | 1 | 1.000 | 1.000 | 1.000 |
| `rbac_bypass` | 1 | 0.000 | 0.000 | 0.000 |
| `scope_escalation` | 1 | 0.000 | 1.000 | 1.000 |

## Interpretation

- **Overall (N=50)**: dual F1 = 0.899, recall = 0.889, FPR = 0.800. WAF1-only F1 = 0.860, WAF2-only F1 = 0.810. Dual gain over WAF2 alone: ΔF1 = +0.089.
- **Char injection**: dual recall = 1.000 (TP=15/15). Best layer: `WAF1 (strict ∪ full)` at recall 1.000.
- **Prompt injection + privilege escalation**: dual recall = 0.867 (TP=13/15). Best layer: `Dual (WAF1 ∪ WAF2)` at recall 0.867.
- **Call-chain composition**: dual recall = 0.800 (TP=12/15). Best layer: `Dual (WAF1 ∪ WAF2)` at recall 0.800.
- **Real vs synthetic gap** (dual): real recall = 0.881, synthetic recall = 1.000 (Δ = -11.9 pp). Synthetic tools may not be well-targeted by current rules — consider this when reading aggregated metrics.
- **Chain block-step**: step-1 (early) dual recall = 1.000; step ≥2 (full-chain) average dual recall = 0.650. Chains that require seeing more steps are harder to catch.

## Reproduction

```bash
# Re-run merge
PYTHONPATH=. python3 -m waf2.rag.scripts.merge_mbench_layers \
    --cases-dir <run-dir> \
    --dataset-dir waf2/rag/eval/m-bench-core/ \
    --out-dir <run-dir>

# Re-render this report
PYTHONPATH=. python3 -m waf2.rag.scripts.report_mbench \
    --merged waf2/rag/eval/runs/2026-05-24-mbench-pilot/cases-mbench-merged.jsonl \
    --out <run-dir>/dual-layer-mbench-report.md
```

- Joined cases: 50
- Git hash: `53688db`
- Generated: 2026-05-24T13:05:14.184728
