# Phase E — Running the Failure Analysis Loop Against Real WAF2

Phase A-D ship the per-case telemetry, JSONL output, auto-derivation rules,
sampling, and report builders. Phase E is the **first real run** against
Docker+Ollama-backed WAF2 to validate the pipeline end-to-end with live data.

The TestClient-based smoke at `waf2/tests/test_phase_e_e2e.py` proves the
artefact format flows through every tool, but only against the static-rule
path (no LLM, no RAG). The real Phase E run uses qwen3:8b + RAG to exercise
R3 / R5 in addition to R1 / R2 / R7.

## Prerequisites

1. WAF2 Docker container running with eval_mode-capable build (current `master`)
2. Ollama exposing `qwen3:8b` on `host.docker.internal:11434`
3. CSIC2010 dataset on disk (already in `waf2/rag/eval/csic2010/`)
4. B-0 dataset on disk (`waf2/rag/eval/prompt-injection-eval.jsonl`)
5. InjecAgent external corpus on disk (`waf2/rag/external/InjecAgent/data/`)

## Step-by-step

```bash
mkdir -p waf2/rag/eval/runs/$(date +%F)-eval-failure-analysis-loop
RUN_DIR=waf2/rag/eval/runs/$(date +%F)-eval-failure-analysis-loop
```

### 9.1 CSIC 100 sample (~10 min)

```bash
python3 waf2/rag/scripts/eval_rag.py \
    --dataset csic --sample 100 \
    --cases-out-dir "$RUN_DIR"
```

Produces: `$RUN_DIR/cases-csic-rag-off.jsonl`, `cases-csic-rag-on.jsonl`,
plus `failures.jsonl` (legacy backwards-compat).

### 9.2 B-0 prompt-injection-eval both modes (~50 min)

```bash
python3 waf2/rag/scripts/eval_prompt_injection.py \
    --mode both \
    --cases-out-dir "$RUN_DIR" \
    --report "$RUN_DIR/b0-report.json"
```

Produces: `$RUN_DIR/cases-b0-rag-off.jsonl`, `cases-b0-rag-on.jsonl`.

### 9.3 B-1 InjecAgent dh_base, limit 30 (~7 min)

A 30-case smoke is enough to validate the B-1 path before committing to a
full 400-case run. If 9.4 / 9.5 / 9.7 look correct, expand to all 4 splits
with `--splits dh_base,ds_base,dh_enhanced,ds_enhanced --limit 100`.

```bash
python3 waf2/rag/scripts/eval_injecagent.py \
    --splits dh_base --limit 30 --rag on \
    --cases-out-dir "$RUN_DIR" \
    --report "$RUN_DIR/b1-report.json"
```

Produces: `$RUN_DIR/cases-b1-dh_base.jsonl`.

### 9.4 Label every cases file

```bash
python3 waf2/rag/scripts/label_failures.py "$RUN_DIR"/cases-*.jsonl
```

Produces: matching `labels-*.jsonl` siblings. Exit code 0 + a warning to
stderr when `unknown > 30%`.

### 9.5 Sample B-1 for manual cause labeling

```bash
python3 waf2/rag/scripts/sample_for_manual.py "$RUN_DIR/cases-b1-dh_base.jsonl"
```

Produces: `$RUN_DIR/b1-sample-30.md` (or `b1-sample-N.md` where N = min(30, size)).

For B-0 / CSIC the full FN+FP+ambiguous list is emitted under `b0-manual.md` /
`csic-manual.md`. Optional — these are small enough to label all of.

### 9.6 Hand-label the 30 B-1 sample

Open `b1-sample-30.md`. For every checklist item, replace the
`__________` placeholder with one of:

- `social_eng_no_marker` (no IPI marker, pure social engineering)
- `carrier_unaware` (LLM saw IPI marker but treated as data, not instructions)
- `deep_nesting` (payload buried beyond depth limit)
- `novel_encoding` (encoder didn't recognize the obfuscation)
- `kb_coverage_gap` (no similar attack in RAG KB)
- `kb_label_noise` (RAG hit, wrong category)
- `threshold_misfit` (router took fast_pass despite score)
- `ambiguous_pattern` (B-1 miscategorized TP)
- `other: <one-liner>` for everything else

The auto-derived `auto: R?/<layer>` annotation alongside each item is just
a hint — feel free to overrule it.

### 9.7 Build the failure analysis report

```bash
python3 waf2/rag/scripts/build_failure_report.py "$RUN_DIR"
```

Produces: `$RUN_DIR/failure-analysis.md`.

Sections of interest:

- **Overview** — total cases, unknown rate (alarm if > 30%)
- **Fix-bucket ROI** — `fix_hint → count → maps_to_change` table
- **Layer / Rule distribution** — sanity check
- **B-1 single-bucket hypothesis** — `intact` / `broken` / `no-data`
- **Cross-run diff** (with `--compare <prior_run_dir>`) — new vs fixed cases by case_id

### 9.8 Decide next steps based on the verdict

- **B-1 intact**: hypothesis holds, queue `harden-waf2-llm-judge-field-isolation` next.
- **B-1 broken**: ≥ 3 of 30 disagree with `social_eng_no_marker`. Re-run
  `sample_for_manual.py --n 100`, hand-label, rebuild report.
- **Unknown > 30%**: rule coverage gap — extend `label_failures.py` R1-R8 or
  acknowledge the gap as out-of-scope for current rules.

### Re-run after a change ships

Once `harden-waf2-llm-judge-field-isolation` (or any downstream change) ships:

```bash
NEW_DIR=waf2/rag/eval/runs/$(date +%F)-after-X
# … rerun 9.1-9.4 against the new container …
python3 waf2/rag/scripts/build_failure_report.py "$NEW_DIR" --compare "$RUN_DIR"
```

The `--compare` block shows how many old FN case_ids disappeared (`fixed:`)
and how many new FN case_ids appeared (`new:`) — a direct measurement of the
change's effect on the failure surface.
