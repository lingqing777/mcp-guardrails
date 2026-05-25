#!/usr/bin/env bash
# run_ablation.sh — Execute one of 7 WAF ablation configurations end-to-end.
#
# Wire ordering (see openspec/changes/add-waf-ablation-eval-harness/design.md D6):
#
#   1 WAF1-only         POST /api/config/waf1 all-on (cc=t,dp=t,rbac=t)
#                       → WAF1 attacks+benign → merge --skip-waf2 → report
#   2 WAF2-only         POST /waf2/config rag=true,react=true
#                       → WAF2 attacks+benign rag-on → merge --skip-waf1 → report
#   3 Full              both stacks all-on (WAF1 cc/dp/rbac on, WAF2 rag+react on)
#                       → WAF1 + WAF2 rag-on+rag-off → merge → report
#   4 Full no-chain     WAF1 callChainEnabled=false
#                       → WAF1 only; cp 3's WAF2 outputs → merge → report
#   5 Full no-dynSQL    WAF1 dynamicPolicyEnabled=false
#                       → WAF1 only; cp 3's WAF2 outputs → merge → report
#   6 Full no-RAG       WAF2 rag_enabled=false (react still on)
#                       → WAF2 only rag-off; cp 3's WAF1; rename rag-off→rag-on slot → merge → report
#   7 Full no-ReAct     WAF2 react_routing_enabled=false (rag still on)
#                       → WAF2 only --react-mode off; cp 3's WAF1; rename rag-on-react-off→rag-on slot → merge → report
#
# Output:
#   <root>/<N>-<slug>/cases-mbench-merged.jsonl
#   <root>/<N>-<slug>/dual-layer-mbench-report.md
#   <root>/<N>-<slug>/summary.tsv
#   <root>/index.tsv (8 fields × N rows; one row appended per ablation completed)
#
# Index TSV columns:
#   ablation_label  char_F1  pi_F1  chain_F1  recall  F1  avg_time_attacks_ms  avg_time_benigns_ms

set -euo pipefail

# ---------- defaults ----------

ABLATION="all"
DATE_TAG="$(date +%Y-%m-%d)"
MODEL=""
MCP_HUB_URL="http://localhost:4000"
MCP_HUB_USER="admin"
MCP_HUB_PASS="guardrails"
WAF2_URL="http://localhost:8081"
ATTACKS_JSONL=""
BENIGNS_JSONL=""
BENIGN_SAMPLE="equal"  # equal | <N> | all
SAMPLE_SEED="42"
ROOT_OVERRIDE=""

# ---------- usage ----------

usage() {
  cat <<EOF
Usage: $0 --ablation {1|2|3|4|5|6|7|all} [--date YYYY-MM-DD] [--model NAME]
                     [--attacks PATH] [--benigns PATH] [--root DIR]
                     [--benign-sample {equal|N|all}] [--sample-seed N]
                     [--mcp-hub URL] [--mcp-hub-user U] [--mcp-hub-pass P] [--waf2 URL]

Defaults:
  --ablation        all
  --date            $(date +%Y-%m-%d)
  --model           (empty; appended to root dir as -<model> when set)
  --attacks         waf2/rag/eval/m-bench-core/attacks.jsonl
  --benigns         waf2/rag/eval/m-bench-core/benign.jsonl
  --benign-sample   equal     # equal = match attacks count; N = explicit; all = full file
  --sample-seed     42        # seed for reproducible random sample
  --root            waf2/rag/eval/runs/<date>-ablation-7way[-<model>]
  --mcp-hub         http://localhost:4000
  --mcp-hub-user    admin
  --mcp-hub-pass    guardrails
  --waf2            http://localhost:8081

Requires the mcp-hub server (port 4000) and WAF2 server (port 8081) to be running.
EOF
}

# ---------- parse args ----------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ablation) ABLATION="$2"; shift 2 ;;
    --date)     DATE_TAG="$2"; shift 2 ;;
    --model)    MODEL="$2"; shift 2 ;;
    --attacks)        ATTACKS_JSONL="$2"; shift 2 ;;
    --benigns)        BENIGNS_JSONL="$2"; shift 2 ;;
    --benign-sample)  BENIGN_SAMPLE="$2"; shift 2 ;;
    --sample-seed)    SAMPLE_SEED="$2"; shift 2 ;;
    --root)           ROOT_OVERRIDE="$2"; shift 2 ;;
    --mcp-hub)        MCP_HUB_URL="$2"; shift 2 ;;
    --mcp-hub-user)   MCP_HUB_USER="$2"; shift 2 ;;
    --mcp-hub-pass)   MCP_HUB_PASS="$2"; shift 2 ;;
    --waf2)           WAF2_URL="$2"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *)          echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

# ---------- paths ----------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

ATTACKS_JSONL="${ATTACKS_JSONL:-waf2/rag/eval/m-bench-core/attacks.jsonl}"
BENIGNS_JSONL="${BENIGNS_JSONL:-waf2/rag/eval/m-bench-core/benign.jsonl}"

if [[ ! -f "$ATTACKS_JSONL" ]]; then
  echo "error: attacks file not found: $ATTACKS_JSONL" >&2
  exit 2
fi
if [[ ! -f "$BENIGNS_JSONL" ]]; then
  echo "error: benigns file not found: $BENIGNS_JSONL" >&2
  exit 2
fi

MODEL_TAG=""
if [[ -n "$MODEL" ]]; then MODEL_TAG="-${MODEL}"; fi

ROOT_DIR="${ROOT_OVERRIDE:-waf2/rag/eval/runs/${DATE_TAG}-ablation-7way${MODEL_TAG}}"
INDEX_TSV="${ROOT_DIR}/index.tsv"
mkdir -p "$ROOT_DIR"

# ---------- mutex (per WAF2 endpoint) ----------

# Prevent two ablation runs from hammering the same Ollama (qwen3:8b is a
# single-GPU/CPU serial worker; concurrent runs cause request queue timeouts).
# Lock key = sha1 of WAF2 base URL — different endpoints can run in parallel.
LOCK_KEY="$(echo -n "$WAF2_URL" | sha1sum | awk '{print $1}' | cut -c1-12)"
LOCK_FILE="/tmp/run_ablation-${LOCK_KEY}.lock"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
  other_pid="$(cat "$LOCK_FILE" 2>/dev/null || echo unknown)"
  echo "error: another ablation run is using $WAF2_URL (lock $LOCK_FILE, pid $other_pid)." >&2
  echo "       wait for it to finish, or use a different --waf2 endpoint." >&2
  exit 4
fi
echo "$$" >&200

# ---------- benign sampling ----------

# Resolve `--benign-sample`:
#   equal → count == number of lines in attacks.jsonl
#   N     → integer count
#   all   → no sampling (use full file)
# When sampling, write a deterministic random sample (python random.sample,
# seeded with --sample-seed) to <root>/_benign_sample.jsonl and re-point
# BENIGNS_JSONL to that file.
sample_benigns_if_requested() {
  if [[ "$BENIGN_SAMPLE" == "all" ]]; then
    echo "[ablation] benign sampling: disabled (using full $BENIGNS_JSONL)" >&2
    return 0
  fi

  local attacks_n
  attacks_n="$(grep -c . "$ATTACKS_JSONL" || true)"
  local target_n
  if [[ "$BENIGN_SAMPLE" == "equal" ]]; then
    target_n="$attacks_n"
  elif [[ "$BENIGN_SAMPLE" =~ ^[0-9]+$ ]]; then
    target_n="$BENIGN_SAMPLE"
  else
    echo "error: --benign-sample must be 'equal', 'all', or a positive integer (got: $BENIGN_SAMPLE)" >&2
    exit 2
  fi

  local out_file="$ROOT_DIR/_benign_sample.jsonl"
  python3 - "$BENIGNS_JSONL" "$out_file" "$target_n" "$SAMPLE_SEED" <<'PY'
import json, random, sys
src, dst, n_str, seed_str = sys.argv[1:5]
n = int(n_str)
seed = int(seed_str)
with open(src, encoding="utf-8") as f:
    rows = [ln for ln in f if ln.strip()]
if n >= len(rows):
    picked = rows
else:
    random.seed(seed)
    picked = random.sample(rows, n)
with open(dst, "w", encoding="utf-8") as f:
    for r in picked:
        f.write(r if r.endswith("\n") else r + "\n")
print(f"[ablation] sampled {len(picked)}/{len(rows)} benigns (seed={seed}) → {dst}",
      file=sys.stderr)
PY
  BENIGNS_JSONL="$out_file"
}

sample_benigns_if_requested

# ---------- helpers ----------

# Login to mcp-hub and stash the session cookie in $MCP_HUB_COOKIES.
# Subsequent /api/config/waf1 POSTs require this cookie.
MCP_HUB_COOKIES=""
mcp_hub_login() {
  if [[ -n "$MCP_HUB_COOKIES" && -f "$MCP_HUB_COOKIES" ]]; then return 0; fi
  MCP_HUB_COOKIES="$ROOT_DIR/_mcp-hub-cookies.txt"
  echo "[ablation] login $MCP_HUB_URL as $MCP_HUB_USER" >&2
  curl -fsS -c "$MCP_HUB_COOKIES" -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"${MCP_HUB_USER}\",\"password\":\"${MCP_HUB_PASS}\"}" \
    "${MCP_HUB_URL}/auth/login" >/dev/null
}

# POST WAF1 config (3 boolean switches)
post_waf1() {
  local cc="$1" dp="$2" rbac="$3"
  mcp_hub_login
  echo "[ablation] POST /api/config/waf1 callChain=$cc dynPolicy=$dp rbacArgs=$rbac" >&2
  curl -fsS -b "$MCP_HUB_COOKIES" -X POST -H "Content-Type: application/json" \
    -d "{\"callChainEnabled\":${cc},\"dynamicPolicyEnabled\":${dp},\"rbacArgsEnabled\":${rbac}}" \
    "${MCP_HUB_URL}/api/config/waf1" >/dev/null
}

# POST WAF2 config (rag + react switches). Use eval_mode for the harness.
post_waf2() {
  local rag="$1" react="$2"
  echo "[ablation] POST /waf2/config rag=$rag react=$react" >&2
  curl -fsS -X POST -H "Content-Type: application/json" \
    -d "{\"rag_enabled\":${rag},\"react_routing_enabled\":${react},\"eval_mode\":true,\"eval_fail_closed\":false}" \
    "${WAF2_URL}/waf2/config" >/dev/null
}

# Run WAF1 on a jsonl into out_dir. Extra args (e.g. --no-call-chain) passed through.
run_waf1() {
  local jsonl="$1" out_dir="$2"
  shift 2
  mkdir -p "$out_dir"
  echo "[ablation] WAF1 → $jsonl → $out_dir ${*:-}" >&2
  node mcp-hub/scripts/run_waf1_on_mbench.mjs \
    --jsonl "$jsonl" \
    --variant both \
    --out-dir "$out_dir" \
    "$@"
}

# Run WAF2 on a jsonl into out_dir with explicit rag/react modes
run_waf2() {
  local jsonl="$1" out_dir="$2" rag_mode="$3" react_mode="$4"
  mkdir -p "$out_dir"
  echo "[ablation] WAF2 → $jsonl → $out_dir (rag=$rag_mode,react=$react_mode)" >&2
  python3 waf2/rag/scripts/run_waf2_on_mbench.py \
    --waf2 "$WAF2_URL" \
    --jsonl "$jsonl" \
    --rag-mode "$rag_mode" \
    --react-mode "$react_mode" \
    --out-dir "$out_dir"
}

# Prepare a dataset dir holding attacks.jsonl + benign.jsonl (merge expects these stems).
# Returns the dataset dir on stdout.
prepare_dataset_dir() {
  local target="$1"
  mkdir -p "$target"
  cp -f "$ATTACKS_JSONL" "$target/attacks.jsonl"
  cp -f "$BENIGNS_JSONL" "$target/benign.jsonl"
  echo "$target"
}

# If user supplied a benign jsonl whose stem != "benign", the harness outputs
# files named cases-mbench-<stem>-*.jsonl. Rename them so merge finds them.
normalize_benign_outputs() {
  local cases_dir="$1"
  local stem
  stem="$(basename "$BENIGNS_JSONL" .jsonl)"
  if [[ "$stem" == "benign" ]]; then return 0; fi
  shopt -s nullglob
  for f in "$cases_dir"/cases-mbench-"${stem}"-*.jsonl; do
    local base
    base="$(basename "$f")"
    local renamed="${base/cases-mbench-${stem}-/cases-mbench-benign-}"
    mv -f "$f" "$cases_dir/$renamed"
  done
  shopt -u nullglob
}

# Normalize attacks the same way (in case user passes a custom path).
normalize_attacks_outputs() {
  local cases_dir="$1"
  local stem
  stem="$(basename "$ATTACKS_JSONL" .jsonl)"
  if [[ "$stem" == "attacks" ]]; then return 0; fi
  shopt -s nullglob
  for f in "$cases_dir"/cases-mbench-"${stem}"-*.jsonl; do
    local base
    base="$(basename "$f")"
    local renamed="${base/cases-mbench-${stem}-/cases-mbench-attacks-}"
    mv -f "$f" "$cases_dir/$renamed"
  done
  shopt -u nullglob
}

# Run merge + report for an ablation dir. Args: out_dir, label, extra_merge_flags...
run_merge_and_report() {
  local out_dir="$1" label="$2"
  shift 2
  local extra_merge_flags=("$@")

  local cases_dir="$out_dir"
  local dataset_dir="$out_dir/_dataset"
  prepare_dataset_dir "$dataset_dir" >/dev/null

  echo "[ablation] merge → $out_dir (label=$label, flags=${extra_merge_flags[*]:-})" >&2
  python3 waf2/rag/scripts/merge_mbench_layers.py \
    --cases-dir "$cases_dir" \
    --dataset-dir "$dataset_dir" \
    --out-dir "$out_dir" \
    --ablation-label "$label" \
    "${extra_merge_flags[@]}"

  echo "[ablation] report → $out_dir" >&2
  python3 waf2/rag/scripts/report_mbench.py \
    --merged "$out_dir/cases-mbench-merged.jsonl" \
    --out "$out_dir/dual-layer-mbench-report.md" \
    --ablation-label "$label" \
    --append-to "$INDEX_TSV"
}

# Slug dir helper: <root>/<N>-<slug>
slug_dir() {
  echo "${ROOT_DIR}/$1"
}

# ---------- ablation 1: WAF1-only ----------

ablation_1() {
  local out_dir; out_dir="$(slug_dir "1-waf1-only")"
  echo "=== Ablation 1: WAF1-only ===" >&2
  post_waf1 true true true
  run_waf1 "$ATTACKS_JSONL" "$out_dir"
  run_waf1 "$BENIGNS_JSONL" "$out_dir"
  normalize_attacks_outputs "$out_dir"
  normalize_benign_outputs "$out_dir"
  run_merge_and_report "$out_dir" "WAF1-only" --skip-waf2
}

# ---------- ablation 2: WAF2-only ----------

ablation_2() {
  local out_dir; out_dir="$(slug_dir "2-waf2-only")"
  echo "=== Ablation 2: WAF2-only ===" >&2
  post_waf2 true true
  run_waf2 "$ATTACKS_JSONL" "$out_dir" on on
  run_waf2 "$BENIGNS_JSONL" "$out_dir" on on
  normalize_attacks_outputs "$out_dir"
  normalize_benign_outputs "$out_dir"
  run_merge_and_report "$out_dir" "WAF2-only" --skip-waf1
}

# ---------- ablation 3: Full ----------

ablation_3() {
  local out_dir; out_dir="$(slug_dir "3-full")"
  echo "=== Ablation 3: Full ===" >&2
  post_waf1 true true true
  post_waf2 true true
  run_waf1 "$ATTACKS_JSONL" "$out_dir"
  run_waf1 "$BENIGNS_JSONL" "$out_dir"
  run_waf2 "$ATTACKS_JSONL" "$out_dir" on on
  run_waf2 "$BENIGNS_JSONL" "$out_dir" on on
  normalize_attacks_outputs "$out_dir"
  normalize_benign_outputs "$out_dir"
  run_merge_and_report "$out_dir" "Full"
}

# Copy WAF2 outputs (rag-on only) from ablation 3 into a new dir.
# Configs 4 and 5 only change WAF1; WAF2 behavior is unchanged so we reuse.
reuse_waf2_from_full() {
  local target="$1"
  local src; src="$(slug_dir "3-full")"
  if [[ ! -d "$src" ]]; then
    echo "error: ablation 3 dir not found ($src); run --ablation 3 first" >&2
    exit 3
  fi
  shopt -s nullglob
  for f in "$src"/cases-mbench-*-rag-on.jsonl; do
    cp -f "$f" "$target/$(basename "$f")"
  done
  shopt -u nullglob
}

# Copy WAF1 outputs (waf1-strict, waf1-full) from ablation 3 into a new dir.
# Configs 6 and 7 only change WAF2; WAF1 behavior is unchanged so we reuse.
reuse_waf1_from_full() {
  local target="$1"
  local src; src="$(slug_dir "3-full")"
  if [[ ! -d "$src" ]]; then
    echo "error: ablation 3 dir not found ($src); run --ablation 3 first" >&2
    exit 3
  fi
  shopt -s nullglob
  for f in "$src"/cases-mbench-*-waf1-strict.jsonl "$src"/cases-mbench-*-waf1-full.jsonl; do
    cp -f "$f" "$target/$(basename "$f")"
  done
  shopt -u nullglob
}

# ---------- ablation 4: Full no-chain ----------

ablation_4() {
  local out_dir; out_dir="$(slug_dir "4-full-no-chain")"
  echo "=== Ablation 4: Full no-chain (callChainEnabled=false) ===" >&2
  mkdir -p "$out_dir"
  post_waf1 false true true
  run_waf1 "$ATTACKS_JSONL" "$out_dir" --no-call-chain
  run_waf1 "$BENIGNS_JSONL" "$out_dir" --no-call-chain
  normalize_attacks_outputs "$out_dir"
  normalize_benign_outputs "$out_dir"
  reuse_waf2_from_full "$out_dir"
  run_merge_and_report "$out_dir" "Full no-chain"
}

# ---------- ablation 5: Full no-dynSQL ----------

ablation_5() {
  local out_dir; out_dir="$(slug_dir "5-full-no-dynsql")"
  echo "=== Ablation 5: Full no-dynSQL (dynamicPolicyEnabled=false) ===" >&2
  mkdir -p "$out_dir"
  post_waf1 true false true
  run_waf1 "$ATTACKS_JSONL" "$out_dir" --no-dyn-policy
  run_waf1 "$BENIGNS_JSONL" "$out_dir" --no-dyn-policy
  normalize_attacks_outputs "$out_dir"
  normalize_benign_outputs "$out_dir"
  reuse_waf2_from_full "$out_dir"
  run_merge_and_report "$out_dir" "Full no-dynSQL"
}

# Move rag-off outputs into the rag-on slot so merge (without --skip-*) sees them.
# Used by ablation 6 (no-RAG): we only have rag-off data but merge's 4-layer join
# expects rag-on; we trick the merge by relabeling the file.
slot_rag_off_as_rag_on() {
  local out_dir="$1"
  shopt -s nullglob
  for f in "$out_dir"/cases-mbench-*-rag-off.jsonl; do
    local base; base="$(basename "$f")"
    local target="${base/-rag-off.jsonl/-rag-on.jsonl}"
    mv -f "$f" "$out_dir/$target"
  done
  shopt -u nullglob
}

# Move rag-on-react-off outputs into the rag-on slot (ablation 7).
slot_react_off_as_rag_on() {
  local out_dir="$1"
  shopt -s nullglob
  for f in "$out_dir"/cases-mbench-*-rag-on-react-off.jsonl; do
    local base; base="$(basename "$f")"
    local target="${base/-rag-on-react-off.jsonl/-rag-on.jsonl}"
    mv -f "$f" "$out_dir/$target"
  done
  shopt -u nullglob
}

# ---------- ablation 6: Full no-RAG ----------

ablation_6() {
  local out_dir; out_dir="$(slug_dir "6-full-no-rag")"
  echo "=== Ablation 6: Full no-RAG (WAF2 rag_enabled=false) ===" >&2
  mkdir -p "$out_dir"
  run_waf2 "$ATTACKS_JSONL" "$out_dir" off on
  run_waf2 "$BENIGNS_JSONL" "$out_dir" off on
  normalize_attacks_outputs "$out_dir"
  normalize_benign_outputs "$out_dir"
  slot_rag_off_as_rag_on "$out_dir"
  reuse_waf1_from_full "$out_dir"
  run_merge_and_report "$out_dir" "Full no-RAG"
}

# ---------- ablation 7: Full no-ReAct ----------

ablation_7() {
  local out_dir; out_dir="$(slug_dir "7-full-no-react")"
  echo "=== Ablation 7: Full no-ReAct (WAF2 react_routing_enabled=false) ===" >&2
  mkdir -p "$out_dir"
  run_waf2 "$ATTACKS_JSONL" "$out_dir" on off
  run_waf2 "$BENIGNS_JSONL" "$out_dir" on off
  normalize_attacks_outputs "$out_dir"
  normalize_benign_outputs "$out_dir"
  slot_react_off_as_rag_on "$out_dir"
  reuse_waf1_from_full "$out_dir"
  run_merge_and_report "$out_dir" "Full no-ReAct"
}

# ---------- dispatcher ----------

case "$ABLATION" in
  1) ablation_1 ;;
  2) ablation_2 ;;
  3) ablation_3 ;;
  4) ablation_4 ;;
  5) ablation_5 ;;
  6) ablation_6 ;;
  7) ablation_7 ;;
  all)
    ablation_1
    ablation_2
    ablation_3
    ablation_4
    ablation_5
    ablation_6
    ablation_7
    ;;
  *)
    echo "unknown --ablation value: $ABLATION (expected 1..7 or all)" >&2
    usage
    exit 2
    ;;
esac

echo ""
echo "[ablation] done. Index TSV: $INDEX_TSV"
echo "[ablation] view summary:  cat $INDEX_TSV"
