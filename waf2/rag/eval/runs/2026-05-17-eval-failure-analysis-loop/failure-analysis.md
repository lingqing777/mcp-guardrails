# Failure Analysis Report — 2026-05-17-eval-failure-analysis-loop

## Overview

- total cases (FN + FP + miscategorized + ambiguous): **266**
- unmatched (rule_id=R8 unknown): **0** (0.0%)

### Per-source

| source | cases | unknown | labeled |
|---|---:|---:|:---:|
| `b0-rag-off` | 165 | 0 | ✓ |
| `b0-rag-on` | 69 | 0 | ✓ |
| `b1-dh-base` | 30 | 0 | ✓ |
| `csic-rag-off` | 1 | 0 | ✓ |
| `csic-rag-on` | 1 | 0 | ✓ |

## Fix-bucket ROI

Counts are number of cases whose `fix_hint` mentions the bucket. Composite hints (e.g. `fath_judge_wrap+field_path_boost`) contribute to every named bucket.

| fix_hint | covered | high-conf | maps_to | status |
|---|---:|---:|---|---|
| `fath_judge_wrap` | 192 | 5 | `harden-waf2-llm-judge-field-isolation` | queued |
| `field_path_boost` | 140 | 0 | `add-field-path-aware-scoring` | unfiled |
| `category_rule_refine` | 54 | 54 | `(local_attack_score refinement)` | unfiled |
| `react_prompt_robustness` | 47 | 0 | `(ReAct prompt / parser robustness)` | unfiled |
| `kb_inject_socialeng` | 18 | 0 | `inject-socialeng-kb-samples` | unfiled |
| `kb_clean` | 2 | 2 | `(KB curation sub-task)` | unfiled |

### Breakdown by source (top fix buckets only)

- `fath_judge_wrap`: b0-rag-off: 137, b0-rag-on: 33, b1-dh-base: 20, csic-rag-off: 1, csic-rag-on: 1
- `field_path_boost`: b0-rag-off: 103, b1-dh-base: 18, b0-rag-on: 17, csic-rag-off: 1, csic-rag-on: 1
- `category_rule_refine`: b0-rag-off: 28, b0-rag-on: 25, b1-dh-base: 1
- `react_prompt_robustness`: b0-rag-off: 29, b0-rag-on: 16, b1-dh-base: 2
- `kb_inject_socialeng`: b0-rag-on: 10, b1-dh-base: 8

## Layer distribution

| layer | count |
|---|---:|
| local_score_low | 140 |
| miscategorized | 54 |
| react_fallback_pass | 47 |
| rag_miss | 18 |
| llm_overrode | 5 |
| rag_wrong | 2 |

## Rule fire counts

| rule_id | count |
|---|---:|
| R2 | 140 |
| R3 | 18 |
| R4 | 2 |
| R5 | 5 |
| R7 | 54 |
| R9 | 47 |

## B-1 single-bucket hypothesis

- sample size: **30** (0 blank)
- dominant-bucket count: **30** (target: `social_eng_no_marker`)
- non-dominant: **0**
- verdict: **intact**

### Cause distribution in sample

| cause | count |
|---|---:|
| `social_eng_no_marker` | 30 |

