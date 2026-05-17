# waf2-evaluation delta

## ADDED Requirements

### Requirement: WAF2 eval-mode response telemetry headers

WAF2 SHALL append diagnostic `X-Waf2-*` response headers when `eval_mode=true` so that evaluation scripts can record per-case decision signals (scores, RAG hits, route, reasons, normalize metadata, latency) without parsing stderr logs. Production behavior MUST be unchanged when `eval_mode=false`.

Headers MUST cover at minimum:

- `X-Waf2-Outcome`: `blocked` or `passed`
- `X-Waf2-Detected-Category`: WAF2's classification when blocked; empty when passed
- `X-Waf2-Local-Score-Total`: numeric, 3 decimal places
- `X-Waf2-Local-Score-Top`: comma-separated `category:score` pairs, top 3 non-zero categories
- `X-Waf2-Rag-Used`: `true` or `false`
- `X-Waf2-Rag-Top-Score`: numeric or empty when rag not used
- `X-Waf2-Rag-Top-Category`: category string or empty
- `X-Waf2-Route`: one of `static_block`, `fast_pass`, `local_llm_one_shot`, `react_deep_inspection`, `knowledge_evidence`, `fallback`
- `X-Waf2-Reasons`: pipe-separated reason tokens
- `X-Waf2-Normalize-Meta`: comma-separated `key=value` pairs (`depth`, `frags`, `decoded`, `b64`)
- `X-Waf2-Latency-Ms`: integer

Single header MUST NOT exceed 256 bytes; overlong fields MUST be truncated with `...` suffix to preserve transport compatibility.

#### Scenario: Headers appear when eval_mode is true

- **WHEN** WAF2 receives a request and `eval_mode=true` is set via `/waf2/config`
- **THEN** the response MUST include every header listed above
- **AND** numeric fields MUST be parseable as numbers
- **AND** categorical fields MUST be one of the documented enums

#### Scenario: Headers absent in production mode

- **WHEN** `eval_mode=false`
- **THEN** the response MUST NOT contain any `X-Waf2-*` header
- **AND** request handling latency MUST be unchanged

#### Scenario: Overlong reasons field truncated safely

- **WHEN** the internal `reasons` list exceeds 256 bytes when joined
- **THEN** `X-Waf2-Reasons` MUST be truncated to fit, ending in `...`
- **AND** WAF2 MUST NOT raise or drop the header

### Requirement: Per-case JSONL output across CSIC / B-0 / B-1 eval scripts

The three evaluation scripts `eval_rag.py`, `eval_prompt_injection.py`, and `eval_injecagent.py` SHALL each emit a per-case JSONL file alongside their existing aggregate reports. Records MUST share a common schema covering identification, expected/actual outcome, WAF2 telemetry (consumed from the response headers above), and dataset-specific context.

Common schema fields:

- `case_id`: stable identifier (row number for B-0/B-1, body-hash for CSIC, plus body-hash cross-check)
- `dataset`: `csic` | `b0` | `b1`
- `round_or_split`: `rag-off` | `rag-on` | `dh_base` | `ds_base` | `dh_enhanced` | `ds_enhanced`
- `expected`: `blocked` | `passed`
- `outcome`: `blocked` | `passed` | `upstream_error`
- `record_kind`: `false_negative` | `false_positive` | `miscategorized` | `ambiguous`
- `method`, `path`, `body`: original request (body truncated to 2KB)
- `local_score_total`, `local_score_top` (parsed dict)
- `rag_used`, `rag_top_score`, `rag_top_category`
- `route`, `reasons` (list), `normalize_meta` (dict), `latency_ms`

Plus dataset-specific fields:

- B-0: `subcategory`, `wrap`, `expected_category`
- B-1: `split`, `attack_type`, `user_tool`, `expected_category`

A case enters the JSONL when ANY of:

- `outcome != expected` (false_negative or false_positive)
- `outcome == blocked AND expected == blocked AND detected_category != expected_category` (miscategorized — TP with wrong label, only when caller supplies expected_category)
- `outcome == passed AND local_score_total >= 0.40`
- `outcome == passed AND rag_top_score >= 0.55`
- `llm_parse_failed == true`

True positives with correct labels and clean negatives MUST NOT be recorded to keep file size proportional to failure volume.

#### Scenario: CSIC FN case is captured with full telemetry

- **WHEN** `eval_rag.py` runs against CSIC with a request that should block but passes
- **THEN** `cases-csic-{round}.jsonl` MUST contain a line for that case
- **AND** the line MUST include `record_kind=false_negative` and all common schema fields
- **AND** `local_score_total` and `route` MUST be parsed from the response headers

#### Scenario: B-1 passed case with high score recorded as ambiguous

- **WHEN** `eval_injecagent.py` runs and a case passes with `local_score_total=0.42`
- **THEN** `cases-b1-{split}.jsonl` MUST contain a line with `record_kind=ambiguous`
- **AND** the line MUST include split-specific fields (`split`, `attack_type`, `user_tool`)

#### Scenario: Clean true positive is not recorded

- **WHEN** an attack case is correctly blocked with no ambiguity signals
- **THEN** no line MUST be written to the per-case JSONL for that case

### Requirement: Failure labeling derives layer / cause / fix from per-case data

A script `label_failures.py` SHALL read a `cases-*.jsonl` and emit a `labels-*.jsonl` with derived bucketing across three dimensions: failure layer, root cause hint, and hypothesized fix. Labels MUST be derivable from the immutable per-case data, so that re-running the labeler after rule updates does not require re-running the eval.

Auto-derivation rules MUST be applied in priority order, first match wins:

- **R1 normalize_miss**: `normalize_meta.frags == 0 AND body contains nested-structure characters`
- **R2 local_score_low**: `local_score_total < 0.35 AND no IPI/encode/sql marker hit AND outcome=passed`
- **R3 rag_miss**: `rag_used=true AND rag_top_score < 0.55`
- **R4 rag_wrong**: `rag_top_score >= 0.60 AND rag_top_category != expected_category AND outcome=passed`
- **R5 llm_overrode**: `local_score_total >= 0.55 AND outcome=passed AND route IN {local_llm_one_shot, react_deep_inspection}`
- **R6 router_too_loose**: `route=fast_pass AND local_score_total >= 0.35`
- **R7 miscategorized**: `outcome=blocked AND detected_category != expected_category`
- **R9 react_fallback_pass**: `route=fallback AND outcome=passed AND local_score_total >= 0.35`
- **R8 unknown** (fallback): no rule matched

Each label record MUST contain: `{case_id, layer, cause_hint, fix_hint, confidence, rule_id}`.

When `unknown` rate exceeds 30% across the input, the labeler MUST emit a stderr warning recommending rule expansion or sampling.

#### Scenario: Case with high local score that passed is labeled llm_overrode

- **WHEN** a per-case record has `local_score_total=0.60, outcome=passed, route=local_llm_one_shot`
- **THEN** `label_failures.py` MUST emit `layer=llm_overrode, rule_id=R5, confidence=high`
- **AND** `fix_hint=fath_judge_wrap`

#### Scenario: Case with low local score and no markers is labeled local_score_low

- **WHEN** a per-case record has `local_score_total=0.20, reasons=['json_fragments'], outcome=passed`
- **THEN** the label MUST be `layer=local_score_low, rule_id=R2, confidence=medium`
- **AND** `fix_hint=fath_judge_wrap+field_path_boost`

#### Scenario: Unknown rate triggers warning

- **WHEN** more than 30% of cases match no R1-R7 rule
- **THEN** the script MUST write a stderr warning naming the affected file
- **AND** exit code MUST remain 0 (warning, not failure)

### Requirement: Manual sampling for high-volume single-bucket validation

A script `sample_for_manual.py` SHALL produce a markdown checklist sampling a configurable subset of cases for manual cause labeling, with a deterministic seed so that the same input produces the same sample. For B-1 the default sample size MUST be 30. For B-0 and CSIC, all FNs/FPs MUST be listed (no sampling).

When the manual-validated portion contains 3 or more cases that contradict the dominant auto-derived bucket (e.g. 3+ B-1 cases NOT belonging to `social_eng_no_marker`), the script MUST emit a stderr warning recommending sample expansion to 100.

The output markdown MUST contain one checklist item per sampled case, including: case_id, truncated body, auto-derived layer, and a blank `cause: __________` field for the user to fill.

#### Scenario: B-1 sample of 30 is deterministic

- **WHEN** `sample_for_manual.py cases-b1-dh_base.jsonl --eval b1 --n 30` is invoked twice on identical input
- **THEN** the two output markdown files MUST be byte-identical
- **AND** the seed MUST be the fixed string documented in the design

#### Scenario: Hypothesis-break triggers expansion warning

- **WHEN** the user has filled in `cause` for the 30 sampled B-1 cases and 4 of them are NOT `social_eng_no_marker`
- **AND** the user re-runs the build_failure_report
- **THEN** the report MUST flag "B-1 single-bucket hypothesis broken (4 ≥ 3)" and recommend extending sampling to 100

### Requirement: Failure analysis report aggregates by hypothesized fix

A script `build_failure_report.py` SHALL aggregate `cases-*.jsonl` + `labels-*.jsonl` + optional manual-validation markdown into a per-fix-bucket report. The report MUST list each `fix_hint` with: covered FN count, high-confidence proportion, source eval/split, and mapping to a queued or unfiled OpenSpec change.

The report MUST include:

- A summary table: `fix_hint → covered_FN_count → maps_to_change`
- The overall `unknown` rate per eval
- The B-1 single-bucket hypothesis verdict (intact / broken)
- Cross-run diff hooks: case_id-stable so the next run can compute "FN fixed by latest change" vs "newly-introduced FN" by set diff

The fix-to-change mapping MUST cover at minimum:

- `fath_judge_wrap → harden-waf2-llm-judge-field-isolation`
- `kb_inject_socialeng → inject-socialeng-kb-samples` (placeholder; change may not exist yet)
- `field_path_boost → add-field-path-aware-scoring` (placeholder)
- `depth_limit_bump → harden-waf2-nested-json-extraction (archived)`
- `route_threshold_tune → evaluate-waf2-rag-react-routing-and-models`
- `category_rule_refine → (uncategorized)`
- `unfixable_in_waf2 → out-of-scope`

#### Scenario: Report shows ROI table for a run

- **WHEN** `build_failure_report.py runs/<date>/` is invoked
- **THEN** `failure-analysis.md` MUST contain the summary table with non-zero counts per fix_hint
- **AND** each row MUST link to a change name (existing or placeholder)

#### Scenario: Cross-run case-id stability enables FN-fixed tracking

- **WHEN** two runs from different commits use the same eval datasets
- **THEN** `case_id` values for the same row MUST match byte-for-byte
- **AND** body-hash cross-check MUST agree for ≥ 95% of cases (small drift allowed if dataset is regenerated)
