# M-Bench-Core Dual-Layer Evaluation Report

**Dataset**: M-Bench-Core (MCP-native attack benchmark)
**Generated**: 2026-05-29 22:25:01
**Run git hash**: `unknown`
**Source**: `waf2\rag\eval\runs\2026-05-29-ablation-7way-qwen2_5-1_5b\2-waf2-only\cases-mbench-merged.jsonl`
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
| `WAF1 (strict ∪ full)` | 0 | 150 | 0 | 150 | 0.000 | 0.000 | 0.000 | 0.000 |
| `WAF2 + RAG (rag_on)` | 78 | 72 | 27 | 123 | 0.743 | 0.520 | 0.612 | 0.180 |
| `Dual (WAF1 ∪ WAF2)` | 78 | 72 | 27 | 123 | 0.743 | 0.520 | 0.612 | 0.180 |

## Table 2 — Per-Family Confusion

Each family's confusion counts that family's attacks + ALL benigns (stable FPR denominator across families).

| family | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| Char injection | `WAF1 (strict ∪ full)` | 0 | 50 | 0 | 150 | 0.000 | 0.000 | 0.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 45 | 5 | 27 | 123 | 0.625 | 0.900 | 0.738 | 0.180 |
|  | `Dual (WAF1 ∪ WAF2)` | 45 | 5 | 27 | 123 | 0.625 | 0.900 | 0.738 | 0.180 |
| Prompt injection + privilege escalation | `WAF1 (strict ∪ full)` | 0 | 50 | 0 | 150 | 0.000 | 0.000 | 0.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 22 | 28 | 27 | 123 | 0.449 | 0.440 | 0.444 | 0.180 |
|  | `Dual (WAF1 ∪ WAF2)` | 22 | 28 | 27 | 123 | 0.449 | 0.440 | 0.444 | 0.180 |
| Call-chain composition | `WAF1 (strict ∪ full)` | 0 | 50 | 0 | 150 | 0.000 | 0.000 | 0.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 11 | 39 | 27 | 123 | 0.289 | 0.220 | 0.250 | 0.180 |
|  | `Dual (WAF1 ∪ WAF2)` | 11 | 39 | 27 | 123 | 0.289 | 0.220 | 0.250 | 0.180 |

## Table 3 — Per-Tool-Universe (real vs synthetic)

Real tools: ['file_read_MCP', 'file_read_MCP_hacker', 'http-client', 'mail', 'server-github', 'supabase', 'woocommerce', 'wordpress']. Synthetic tools are any other `<server>` namespace (XML parsers, image processors, etc., introduced to cover attack categories absent from the real tool universe).

| universe | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| real | `WAF1 (strict ∪ full)` | 0 | 144 | 0 | 149 | 0.000 | 0.000 | 0.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 74 | 70 | 27 | 122 | 0.733 | 0.514 | 0.604 | 0.181 |
|  | `Dual (WAF1 ∪ WAF2)` | 74 | 70 | 27 | 122 | 0.733 | 0.514 | 0.604 | 0.181 |
| synthetic | `WAF1 (strict ∪ full)` | 0 | 6 | 0 | 1 | 0.000 | 0.000 | 0.000 | 0.000 |
|  | `WAF2 + RAG (rag_on)` | 4 | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 | 0.000 |
|  | `Dual (WAF1 ∪ WAF2)` | 4 | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 | 0.000 |

## Table 4 — Hard-neg vs Template FP Breakdown

Hard-neg benigns (`source="handcrafted"`) are paired with attacks and intentionally use attack-shaped parameters with business-normal semantics. Template benigns (`source="template"`) cover the stable business baseline.

| layer | handcrafted FP / total | template FP / total | Δpp (handcrafted − template) | overblock? |
|---|---|---|---|---|
| `WAF1 (strict ∪ full)` | 0 / 46 (0.0%) | 0 / 104 (0.0%) | +0.0 pp | no |
| `WAF2 + RAG (rag_on)` | 12 / 46 (26.1%) | 15 / 104 (14.4%) | +11.7 pp | **⚠ OVERBLOCK** |
| `Dual (WAF1 ∪ WAF2)` | 12 / 46 (26.1%) | 15 / 104 (14.4%) | +11.7 pp | **⚠ OVERBLOCK** |

> **⚠ Callout — Hard-neg overblock detected** on layer(s): `WAF2 + RAG (rag_on)`, `Dual (WAF1 ∪ WAF2)`. Handcrafted FP rate exceeds template FP rate by ≥10 percentage points. This indicates the system is over-sensitive to attack-shaped benigns. Inspect the handcrafted samples (search for `source="handcrafted"` + `classification.<layer>="FP"` in the merged JSONL) to audit which patterns are tripping.

## Table 5 — Chain Block-Step Distribution

Call-chain attacks grouped by `expected_block_step` (the latest step at which the system must block to count as TP).

| expected_block_step | n | layer | TP | Recall |
|---|---|---|---|---|
| 1 | 14 | `WAF1 (strict ∪ full)` | 0 | 0.000 |
|  |  | `WAF2 + RAG (rag_on)` | 0 | 0.000 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 0 | 0.000 |
| 2 | 27 | `WAF1 (strict ∪ full)` | 0 | 0.000 |
|  |  | `WAF2 + RAG (rag_on)` | 9 | 0.333 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 9 | 0.333 |
| 3 | 9 | `WAF1 (strict ∪ full)` | 0 | 0.000 |
|  |  | `WAF2 + RAG (rag_on)` | 2 | 0.222 |
|  |  | `Dual (WAF1 ∪ WAF2)` | 2 | 0.222 |

## Table 6 — Per-Subcategory Recall

Sorted by sample count desc.

| subcategory | n | waf1_union recall | rag_on recall | dual recall |
|---|---|---|---|---|
| `credential_theft` | 12 | 0.000 | 0.083 | 0.083 |
| `data_exfiltration` | 12 | 0.000 | 0.250 | 0.250 |
| `sql_injection` | 10 | 0.000 | 0.900 | 0.900 |
| `direct_pi` | 10 | 0.000 | 0.700 | 0.700 |
| `recon_then_exploit` | 10 | 0.000 | 0.500 | 0.500 |
| `xss` | 8 | 0.000 | 1.000 | 1.000 |
| `indirect_pi` | 8 | 0.000 | 0.750 | 0.750 |
| `jailbreak` | 8 | 0.000 | 0.375 | 0.375 |
| `tool_poisoning` | 8 | 0.000 | 0.250 | 0.250 |
| `supabase_lethal_trifecta` | 8 | 0.000 | 0.250 | 0.250 |
| `prompt_injection_to_exfil` | 8 | 0.000 | 0.000 | 0.000 |
| `prompt_leak` | 7 | 0.000 | 0.286 | 0.286 |
| `command_injection` | 6 | 0.000 | 1.000 | 1.000 |
| `path_traversal` | 6 | 0.000 | 1.000 | 1.000 |
| `ssrf` | 6 | 0.000 | 1.000 | 1.000 |
| `sensitive_files` | 5 | 0.000 | 0.200 | 0.200 |
| `dangerous_operations` | 5 | 0.000 | 1.000 | 1.000 |
| `rbac_bypass` | 5 | 0.000 | 0.200 | 0.200 |
| `xxe` | 4 | 0.000 | 1.000 | 1.000 |
| `scope_escalation` | 4 | 0.000 | 0.250 | 0.250 |

## Interpretation

- **Overall (N=300)**: dual F1 = 0.612, recall = 0.520, FPR = 0.180. WAF1-only F1 = 0.000, WAF2-only F1 = 0.612. Dual gain over WAF2 alone: ΔF1 = +0.000.
- **Char injection**: dual recall = 0.900 (TP=45/50). Best layer: `WAF2 + RAG (rag_on)` at recall 0.900.
- **Prompt injection + privilege escalation**: dual recall = 0.440 (TP=22/50). Best layer: `WAF2 + RAG (rag_on)` at recall 0.440.
- **Call-chain composition**: dual recall = 0.220 (TP=11/50). Best layer: `WAF2 + RAG (rag_on)` at recall 0.220.
- **Real vs synthetic gap** (dual): real recall = 0.514, synthetic recall = 0.667 (Δ = -15.3 pp). Synthetic tools may not be well-targeted by current rules — consider this when reading aggregated metrics.
- **Chain block-step**: step-1 (early) dual recall = 0.000; step ≥2 (full-chain) average dual recall = 0.278. Step depth has minor effect on catchability here.

## Reproduction

```bash
# Re-run merge
PYTHONPATH=. python3 -m waf2.rag.scripts.merge_mbench_layers \
    --cases-dir <run-dir> \
    --dataset-dir waf2/rag/eval/m-bench-core/ \
    --out-dir <run-dir>

# Re-render this report
PYTHONPATH=. python3 -m waf2.rag.scripts.report_mbench \
    --merged waf2\rag\eval\runs\2026-05-29-ablation-7way-qwen2_5-1_5b\2-waf2-only\cases-mbench-merged.jsonl \
    --out <run-dir>/dual-layer-mbench-report.md
```

- Joined cases: 300
- Git hash: `unknown`
- Generated: 2026-05-29T22:25:01.045461
