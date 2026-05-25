# waf-ablation-evaluation capability

## ADDED Requirements

### Requirement: The harness SHALL support exactly 7 ablation configurations as a closed set

The ablation harness SHALL recognize and run exactly the following 7 ablation configurations, each identified by a stable `ablation_label` string used across artifacts (file names, TSV columns, run subdirectories):

| # | ablation_label | WAF1 switches | WAF2 round(s) | merge skip |
|---|---|---|---|---|
| 1 | `WAF1-only` | all enabled | (none) | `--skip-waf2` |
| 2 | `WAF2-only` | (not run) | rag-on | `--skip-waf1` |
| 3 | `Full` | all enabled | rag-on (+ rag-off optional) | (none) |
| 4 | `Full no-chain` | callChainEnabled=false | rag-on | (none) |
| 5 | `Full no-dynSQL` | dynamicPolicyEnabled=false | rag-on | (none) |
| 6 | `Full no-RAG` | all enabled | rag-off | (none) |
| 7 | `Full no-ReAct` | all enabled | rag-on + react-off | (none) |

Adding a new ablation configuration MUST require updating this spec section, design.md D1, and the harness's enum (`run_ablation.sh` or equivalent). Removing a configuration MUST be done via a new change proposal.

#### Scenario: Harness rejects unknown ablation label

- **WHEN** a harness wrapper receives `--ablation-label "Full no-rbac"` (not in the 7 closed set)
- **THEN** the wrapper SHALL exit with a non-zero code and a clear error listing the 7 allowed labels

#### Scenario: WAF1-only and WAF2-only are mutually exclusive at merge time

- **WHEN** `merge_mbench_layers.py --skip-waf1 --skip-waf2` is invoked
- **THEN** the script SHALL exit with a non-zero code stating that at least one layer must be evaluated

### Requirement: WAF2 harness SHALL accept --react-mode flag mirroring --rag-mode

`waf2/rag/scripts/run_waf2_on_mbench.py` SHALL accept a new cli flag `--react-mode {on|off|both}` that mirrors the existing `--rag-mode` flag in semantics and wiring.

For each `(rag_state, react_state)` combination produced by the cross-product of `--rag-mode` and `--react-mode`:
- The harness SHALL `POST /waf2/config` with body `{ "rag_enabled": <rag_state>, "react_routing_enabled": <react_state> }` before evaluating any case in that round
- The harness SHALL await a 200 response before starting the round
- After the round completes, the harness SHALL emit a JSONL file whose name reflects both states (see Scenario below)

The default value of `--react-mode` SHALL be `on` to preserve backward compatibility with existing scripts (e.g., M-Bench-Core's main run).

#### Scenario: File naming with react-mode default

- **WHEN** `--rag-mode on --react-mode on` (defaults)
- **THEN** the output file MUST be `cases-mbench-attacks-rag-on.jsonl` (legacy name, no react suffix)

#### Scenario: File naming with react-mode off

- **WHEN** `--rag-mode on --react-mode off`
- **THEN** the output file MUST be `cases-mbench-attacks-rag-on-react-off.jsonl`

#### Scenario: --react-mode both produces two rounds

- **WHEN** `--rag-mode on --react-mode both` is invoked
- **THEN** the harness MUST run 2 rounds: rag-on + react-on, then rag-on + react-off
- **AND** both output files MUST be written

### Requirement: merge SHALL support --skip-waf1 and --skip-waf2 to evaluate single-layer ablations

`waf2/rag/scripts/merge_mbench_layers.py` SHALL accept two new mutually-exclusive flags:

- `--skip-waf1` — WAF1 strict + WAF1 full layer files are NOT required; per-case `waf1_union` is treated as `false`; `dual = waf2_full` (or `rag_off` if `--use-rag-off`)
- `--skip-waf2` — rag-on + rag-off layer files are NOT required; per-case `waf2_full` is treated as `false`; `dual = waf1_union`

When neither flag is set (default), the behavior MUST match the pre-change implementation (all 4 layer files required for inner-join).

Merged JSONL records SHALL include a new top-level field `skipped_layers` (array of strings, each `"waf1"` or `"waf2"`, empty array in default mode) and `ablation_label` (string, passed from `--ablation-label` cli flag, defaults to `""`).

#### Scenario: --skip-waf2 produces merged file without WAF2 fields

- **GIVEN** a run directory with only `cases-mbench-attacks-waf1-strict.jsonl` + `cases-mbench-attacks-waf1-full.jsonl`
- **WHEN** `merge_mbench_layers.py --skip-waf2 --ablation-label "WAF1-only"` is invoked
- **THEN** the merged JSONL MUST be produced with `skipped_layers: ["waf2"]`
- **AND** each record's `rag_on` and `rag_off` nested objects MUST be `null` (or absent)
- **AND** each record's `dual.blocked` MUST equal `waf1_union.blocked`

#### Scenario: --skip-waf1 + --skip-waf2 rejected

- **WHEN** both flags are passed
- **THEN** the script MUST exit non-zero with message "at least one layer must be evaluated"

### Requirement: report SHALL emit summary.tsv with one TSV row per run

`waf2/rag/scripts/report_mbench.py` SHALL, in addition to the existing Markdown report, write a file `summary.tsv` to the same output directory containing a single line with TAB-separated fields in this exact order:

```
ablation_label \t char_F1 \t pi_F1 \t chain_F1 \t recall \t F1 \t avg_time_attacks_ms \t avg_time_benigns_ms
```

Field definitions:

| Field | Definition |
|---|---|
| `ablation_label` | The string passed via `--ablation-label` cli flag (free text, e.g. `"Full no-chain"`); empty string if not provided |
| `char_F1` | F1 score of the `dual` layer restricted to attacks with `family == "char_injection"`. TP/FN drawn from char_injection attacks; FP/TN drawn from all benigns. Computed as `2·P·R / (P+R)`, formatted to 3 decimal places |
| `pi_F1` | Same as `char_F1` but for `family == "prompt_injection_and_priv_esc"` |
| `chain_F1` | Same as `char_F1` but for `family == "call_chain"` |
| `recall` | Overall dual-layer recall across all attacks, formatted to 3 decimal places |
| `F1` | Overall dual-layer F1 across all cases (attacks + benigns), formatted to 3 decimal places |
| `avg_time_attacks_ms` | Mean per-case pipeline latency (sum of activated layers' `latency_ms`), restricted to `label == "attack"`, formatted to 1 decimal place |
| `avg_time_benigns_ms` | Same but restricted to `label == "benign"` |

The file MUST NOT have a header line, and MUST end with a newline. Fields MUST NOT contain literal tabs (string sanitization required for `ablation_label`).

#### Scenario: summary.tsv has exactly one line

- **WHEN** `report_mbench.py --merged X --out Y.md --ablation-label "Full"` is invoked
- **THEN** `summary.tsv` in the same directory as `Y.md` MUST contain exactly 1 line of 8 TAB-separated fields
- **AND** the file MUST end with `\n`

#### Scenario: AvgTime uses activated-layers sum

- **GIVEN** a case with `waf1_strict.latency_ms = 2.0`, `waf1_full.latency_ms = 3.0`, `rag_on.latency_ms = 15000.0`
- **AND** the ablation is `Full` (all three layers activated)
- **THEN** that case contributes `2.0 + 3.0 + 15000.0 = 15005.0` to the AvgTime numerator

- **GIVEN** the same case
- **AND** the ablation is `WAF1-only` (only waf1 layers activated, skipped_layers contains `"waf2"`)
- **THEN** that case contributes `2.0 + 3.0 = 5.0` to the AvgTime numerator

### Requirement: report SHALL support --append-to for cross-ablation index.tsv accumulation

`report_mbench.py` SHALL accept a new cli flag `--append-to <path>` that, when present, MUST after writing the per-run `summary.tsv`, also append that same line to the file at `<path>` (creating the file if absent). Concurrent appends MUST be safe (use `open(..., "a")` with single-line atomic write, or `flock` if available).

The accumulated `index.tsv` file MUST therefore contain N lines after N ablations have completed, each line being the summary of one ablation. Order in the file MUST match append order (chronological).

#### Scenario: After 7 ablations, index.tsv has 7 lines

- **WHEN** all 7 ablation configurations have run with `--append-to <root>/index.tsv`
- **THEN** `wc -l <root>/index.tsv` MUST report exactly 7
- **AND** column 1 of each line MUST be one of the 7 closed-set ablation_label values

#### Scenario: Re-running an ablation appends a duplicate line

- **GIVEN** `index.tsv` already contains a `"Full"` line
- **WHEN** the `Full` ablation is re-run with the same `--append-to`
- **THEN** `index.tsv` MUST gain a second `"Full"` line (with updated metrics) — de-duplication is NOT a requirement of this spec; users handle de-dup downstream (e.g., `awk '!seen[$1]++'`)

### Requirement: Per-ablation run directory SHALL follow `<NN>-<kebab-label>` naming convention

Each of the 7 ablations SHALL produce a run subdirectory under `waf2/rag/eval/runs/<date>-ablation-7way/`, named `<NN>-<kebab-label>` where:

- `<NN>` is the 1-digit configuration number (`1`-`7`) matching D1 / the requirement above
- `<kebab-label>` is the ablation label lowercased, with spaces replaced by `-`, e.g. `"Full no-chain" → "full-no-chain"`

Each subdirectory MUST contain at minimum:
- `attacks/` (when WAF1 is run for this ablation) — WAF1 jsonl outputs
- `cases-mbench-attacks-*.jsonl` (when WAF2 is run for this ablation) — WAF2 jsonl outputs
- `cases-mbench-merged.jsonl` — merge output
- `dual-layer-report.md` — Markdown report
- `summary.tsv` — 1-line TSV

#### Scenario: All 7 subdirectories present after end-to-end run

- **WHEN** the 7-ablation end-to-end sequence completes
- **THEN** `ls waf2/rag/eval/runs/<date>-ablation-7way/` MUST list at least these 7 subdirectories:
  - `1-waf1-only/`
  - `2-waf2-only/`
  - `3-full/`
  - `4-full-no-chain/`
  - `5-full-no-dynsql/`
  - `6-full-no-rag/`
  - `7-full-no-react/`
- **AND** each subdirectory MUST contain `summary.tsv`

### Requirement: Shared WAF2 round artifacts SHALL be reusable across Full / Full no-chain / Full no-dynSQL via documented copy

Because ablation configurations 3 / 4 / 5 all use identical WAF2 inputs (the WAF1 stage switches do not change `args` or `tool` passed to WAF2), the harness wrapper SHALL implement WAF2 output reuse to avoid re-running expensive LLM calls. Specifically, the wrapper SHALL:

- For configuration 3 (Full), run WAF2 rag-on (and rag-off) from scratch and write outputs to `3-full/`
- For configurations 4 and 5, copy (NOT symlink) `cases-mbench-*-rag-on.jsonl` from `3-full/` into their respective subdirectories before invoking merge

The wrapper script (`run_ablation.sh` or equivalent) SHALL contain an explicit comment block documenting the reuse strategy. The wrapper SHALL be idempotent — re-running configurations 4 / 5 with config 3's outputs already present MUST NOT trigger any WAF2 LLM call, and MUST NOT overwrite existing files unless `--force` is passed.

Copy (not symlink) is mandated so that each subdirectory remains self-contained for git commit and archive purposes.

#### Scenario: Reuse documented in wrapper script

- **WHEN** a developer reads `run_ablation.sh` (or wrapper of choice)
- **THEN** the script MUST contain a comment block explaining the WAF2 reuse strategy for configs 3 / 4 / 5
- **AND** the script MUST NOT silently re-run WAF2 LLM calls for configs 4 / 5 if config 3's outputs already exist (idempotent re-run)

#### Scenario: Copy preserves self-contained subdirectories

- **GIVEN** `3-full/cases-mbench-attacks-rag-on.jsonl` exists
- **WHEN** the wrapper executes configuration 4 (no-chain)
- **THEN** `4-full-no-chain/cases-mbench-attacks-rag-on.jsonl` MUST be a regular file (not a symlink)
- **AND** its content MUST be byte-identical to the source file
