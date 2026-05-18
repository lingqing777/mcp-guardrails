# Failure Analysis Report — 2026-05-17-react-fallback-rag-rescue

## Overview

- total cases (FN + FP + miscategorized + ambiguous): **87**
- unmatched (rule_id=R8 unknown): **0** (0.0%)

### Per-source

| source | cases | unknown | labeled |
|---|---:|---:|:---:|
| `b0-rag-on` | 57 | 0 | ✓ |
| `csic-rag-off` | 15 | 0 | ✓ |
| `csic-rag-on` | 15 | 0 | ✓ |

## Fix-bucket ROI

Counts are number of cases whose `fix_hint` mentions the bucket. Composite hints (e.g. `fath_judge_wrap+field_path_boost`) contribute to every named bucket.

| fix_hint | covered | high-conf | maps_to | status |
|---|---:|---:|---|---|
| `fath_judge_wrap` | 51 | 0 | `harden-waf2-llm-judge-field-isolation` | queued |
| `field_path_boost` | 47 | 0 | `add-field-path-aware-scoring` | unfiled |
| `category_rule_refine` | 25 | 25 | `(local_attack_score refinement)` | unfiled |
| `kb_inject_socialeng` | 10 | 0 | `inject-socialeng-kb-samples` | unfiled |
| `react_prompt_robustness` | 4 | 0 | `(ReAct prompt / parser robustness)` | unfiled |
| `kb_clean` | 1 | 1 | `(KB curation sub-task)` | unfiled |

### Breakdown by source (top fix buckets only)

- `fath_judge_wrap`: b0-rag-on: 21, csic-rag-off: 15, csic-rag-on: 15
- `field_path_boost`: b0-rag-on: 17, csic-rag-off: 15, csic-rag-on: 15
- `category_rule_refine`: b0-rag-on: 25
- `kb_inject_socialeng`: b0-rag-on: 10
- `react_prompt_robustness`: b0-rag-on: 4

## Layer distribution

| layer | count |
|---|---:|
| local_score_low | 47 |
| miscategorized | 25 |
| rag_miss | 10 |
| react_fallback_pass | 4 |
| rag_wrong | 1 |

## Rule fire counts

| rule_id | count |
|---|---:|
| R2 | 47 |
| R3 | 10 |
| R4 | 1 |
| R7 | 25 |
| R9 | 4 |

