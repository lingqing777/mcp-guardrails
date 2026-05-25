"""M-Bench-Core: render dual-layer report.

Input: cases-mbench-merged.jsonl (produced by merge_mbench_layers.py).
Output: dual-layer-mbench-report.md with 6 tables + interpretation:
  Section 1: Header & methodology (dataset version, run date, layers, RAG mode,
             hardware, fairness disclosures)
  Section 2: Table 1 — Overall confusion (TP/FN/FP/TN/Prec/Recall/F1/FPR ×3 layers)
  Section 3: Table 2 — Per-family confusion (3 families × 3 layers)
  Section 4: Table 3 — Per-tool-universe (real vs synthetic × 3 layers)
  Section 5: Table 4 — Hard-neg vs template FP breakdown (callout if ≥10pp gap)
  Section 6: Table 5 — Chain block-step distribution (expected_block_step ∈ {1..4})
  Section 7: Table 6 — Per-subcategory recall matrix
  Footer: reproduction details (source jsonl + commands + git hash if available)

F1 here is the *real* F1 using actual precision (M-Bench-Core has benigns, so
TN/FP are measurable — unlike B-0 which had to assume precision=1).

See openspec/changes/add-mbench-core-attack-benchmark/design.md (D10).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------- constants ----------

LAYERS = ["waf1_union", "rag_on", "dual"]
LAYER_LABELS = {
    "waf1_union": "WAF1 (strict ∪ full)",
    "rag_on": "WAF2 + RAG (rag_on)",
    "dual": "Dual (WAF1 ∪ WAF2)",
}

FAMILIES = ["char_injection", "prompt_injection_and_priv_esc", "call_chain"]
FAMILY_LABELS = {
    "char_injection": "Char injection",
    "prompt_injection_and_priv_esc": "Prompt injection + privilege escalation",
    "call_chain": "Call-chain composition",
}

# Real MCP servers used in this project (from config/mcp-servers.json + demo).
# Any tool whose <server> namespace is in this set is considered "real";
# everything else is "synthetic".
REAL_SERVERS = {
    "woocommerce", "wordpress", "supabase", "mail",
    "file_read_MCP", "file_read_MCP_hacker",
    "http-client", "server-github",
}

HARD_NEG_OVERBLOCK_THRESHOLD_PP = 10.0  # percentage points

FAIRNESS_DISCLOSURES = """## Fairness Disclosures

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
"""


# ---------- IO ----------


def load_merged(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"missing merged file: {path}")
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            out.append(json.loads(ln))
    return out


def _git_hash() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


# ---------- universe classification ----------


def tool_universe(rec: dict) -> str:
    """Return 'real' or 'synthetic' for a merged case record.

    For single-step records, inspect `tool`. For multi-step, inspect every
    step's tool — if any step uses a synthetic server, the case counts as
    synthetic.
    """
    if rec.get("is_multi_step"):
        steps = rec.get("steps") or []
        tools = [s.get("tool", "") for s in steps if isinstance(s, dict)]
    else:
        tools = [rec.get("tool", "")]
    for t in tools:
        server = t.split("__")[0] if "__" in t else t
        if server and server not in REAL_SERVERS:
            return "synthetic"
    return "real"


# ---------- confusion matrix ----------


def confusion(records: list[dict], layer: str) -> dict[str, Any]:
    """Compute TP/FN/FP/TN + precision/recall/F1/FPR for one layer."""
    tp = fn = fp = tn = 0
    for rec in records:
        cls = rec.get("classification", {}).get(layer, "")
        if cls == "TP":
            tp += 1
        elif cls == "FN":
            fn += 1
        elif cls == "FP":
            fp += 1
        elif cls == "TN":
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "fpr": fpr,
        "n": tp + fn + fp + tn,
    }


# ---------- TSV summary (per-run + cross-ablation index) ----------


def active_layers(record: dict) -> list[str]:
    """Return merged-record slot names whose latency_ms contributes to AvgTime.

    Rule (matches design.md D5 + spec.md "AvgTime uses activated-layers sum"):
      - WAF1 skipped → exclude waf1_strict, waf1_full
      - WAF2 skipped → exclude rag_on, rag_off
      - rag_off is only included when it carries real data (i.e. not a stub
        from the wrapper script and not marked _skipped); harness-stub rows
        carry `_stub: true` or `_skipped: true`
      - rag_on is always the WAF2 primary slot when WAF2 is active
    """
    skipped = set(record.get("skipped_layers") or [])
    active: list[str] = []
    if "waf1" not in skipped:
        active.extend(["waf1_strict", "waf1_full"])
    if "waf2" not in skipped:
        active.append("rag_on")
        rag_off = record.get("rag_off") or {}
        # Only count rag_off latency when it carries real harness data
        if rag_off and not rag_off.get("_skipped") and not rag_off.get("_stub"):
            active.append("rag_off")
    return active


def compute_avg_time_ms(records: list[dict], label: str) -> float:
    """Mean per-case sum of activated-layers latency_ms, filtered by label."""
    totals: list[float] = []
    for rec in records:
        if rec.get("label") != label:
            continue
        slot_total = 0.0
        for slot in active_layers(rec):
            layer = rec.get(slot) or {}
            try:
                slot_total += float(layer.get("latency_ms", 0) or 0)
            except (TypeError, ValueError):
                pass
        totals.append(slot_total)
    if not totals:
        return 0.0
    return sum(totals) / len(totals)


def compute_summary_metrics(records: list[dict]) -> dict[str, float]:
    """Return the 7 metric fields written to summary.tsv (everything except label)."""
    families = ["char_injection", "prompt_injection_and_priv_esc", "call_chain"]

    def _f1_for_family(fam: str) -> float:
        sub = [r for r in records if r.get("family") == fam or r.get("label") == "benign"]
        return confusion(sub, "dual")["f1"]

    overall = confusion(records, "dual")
    return {
        "char_F1": _f1_for_family("char_injection"),
        "pi_F1": _f1_for_family("prompt_injection_and_priv_esc"),
        "chain_F1": _f1_for_family("call_chain"),
        "recall": overall["recall"],
        "F1": overall["f1"],
        "avg_time_attacks_ms": compute_avg_time_ms(records, "attack"),
        "avg_time_benigns_ms": compute_avg_time_ms(records, "benign"),
    }


def _sanitize_label(label: str) -> str:
    """Tabs / newlines would break TSV; replace with spaces."""
    return (label or "").replace("\t", " ").replace("\n", " ").replace("\r", " ")


def format_summary_tsv_row(ablation_label: str, metrics: dict[str, float]) -> str:
    """8 TAB-separated fields, no trailing newline.

    Column order (matches spec waf-ablation-evaluation Requirement 'report SHALL
    emit summary.tsv'): ablation_label, char_F1, pi_F1, chain_F1, recall, F1,
    avg_time_attacks_ms, avg_time_benigns_ms.
    """
    return "\t".join([
        _sanitize_label(ablation_label),
        f"{metrics['char_F1']:.3f}",
        f"{metrics['pi_F1']:.3f}",
        f"{metrics['chain_F1']:.3f}",
        f"{metrics['recall']:.3f}",
        f"{metrics['F1']:.3f}",
        f"{metrics['avg_time_attacks_ms']:.1f}",
        f"{metrics['avg_time_benigns_ms']:.1f}",
    ])


def write_summary_tsv(out_dir: Path, ablation_label: str, metrics: dict[str, float]) -> Path:
    out_path = out_dir / "summary.tsv"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    row = format_summary_tsv_row(ablation_label, metrics)
    out_path.write_text(row + "\n", encoding="utf-8")
    return out_path


def append_to_index(index_path: Path, ablation_label: str, metrics: dict[str, float]) -> None:
    """Append summary row to cross-ablation index.tsv (create if absent)."""
    index_path.parent.mkdir(parents=True, exist_ok=True)
    row = format_summary_tsv_row(ablation_label, metrics)
    with index_path.open("a", encoding="utf-8") as fh:
        fh.write(row + "\n")


# ---------- table builders ----------


def build_table_overall(records: list[dict]) -> dict[str, dict]:
    return {layer: confusion(records, layer) for layer in LAYERS}


def build_table_per_family(records: list[dict]) -> dict[str, dict[str, dict]]:
    """{family: {layer: confusion}}"""
    out: dict[str, dict[str, dict]] = {}
    for family in FAMILIES:
        sub = [r for r in records if r.get("family") == family]
        # Include the corresponding benigns: for char_injection / pi_priv_esc,
        # all benigns count (since benigns aren't family-scoped — they're
        # paired against arbitrary attacks). For call_chain, benigns
        # share the same denominator (we don't double-count benigns).
        # Per design: per-family confusion uses attacks of that family +
        # ALL benigns (so FPR is a stable denominator across families).
        benigns = [r for r in records if r.get("label") == "benign"]
        family_records = sub + benigns
        out[family] = {layer: confusion(family_records, layer) for layer in LAYERS}
    return out


def build_table_per_universe(records: list[dict]) -> dict[str, dict[str, dict]]:
    """{universe: {layer: confusion}}"""
    out: dict[str, dict[str, dict]] = {}
    for universe in ["real", "synthetic"]:
        sub = [r for r in records if tool_universe(r) == universe]
        out[universe] = {layer: confusion(sub, layer) for layer in LAYERS}
    return out


def build_table_hardneg_breakdown(records: list[dict]) -> dict[str, Any]:
    """For each layer, split FP count by benign source (handcrafted vs template).

    Returns:
      {
        layer: {
          'handcrafted_total': int, 'handcrafted_fp': int, 'handcrafted_fp_rate': float,
          'template_total': int, 'template_fp': int, 'template_fp_rate': float,
          'gap_pp': float,    # handcrafted_fp_rate - template_fp_rate, in percentage points
          'overblock_flag': bool,
        }
      }
    """
    benigns = [r for r in records if r.get("label") == "benign"]
    hc = [r for r in benigns if r.get("source") == "handcrafted"]
    tp_ = [r for r in benigns if r.get("source") == "template"]
    out: dict[str, Any] = {}
    for layer in LAYERS:
        hc_fp = sum(
            1 for r in hc
            if r.get("classification", {}).get(layer) == "FP"
        )
        tp_fp = sum(
            1 for r in tp_
            if r.get("classification", {}).get(layer) == "FP"
        )
        hc_rate = (hc_fp / len(hc)) if hc else 0.0
        tp_rate = (tp_fp / len(tp_)) if tp_ else 0.0
        gap_pp = (hc_rate - tp_rate) * 100
        out[layer] = {
            "handcrafted_total": len(hc),
            "handcrafted_fp": hc_fp,
            "handcrafted_fp_rate": hc_rate,
            "template_total": len(tp_),
            "template_fp": tp_fp,
            "template_fp_rate": tp_rate,
            "gap_pp": gap_pp,
            "overblock_flag": gap_pp >= HARD_NEG_OVERBLOCK_THRESHOLD_PP,
        }
    return out


def build_table_chain_block_step(records: list[dict]) -> dict[int, dict[str, dict]]:
    """For call_chain attacks only, group by expected_block_step ∈ {1,2,3,4}.

    {step: {layer: {recall, n}}}
    """
    chain_attacks = [
        r for r in records
        if r.get("family") == "call_chain" and r.get("label") == "attack"
    ]
    by_step: dict[int, list[dict]] = defaultdict(list)
    for r in chain_attacks:
        step = r.get("expected_block_step")
        if isinstance(step, int) and 1 <= step <= 4:
            by_step[step].append(r)
    out: dict[int, dict[str, dict]] = {}
    for step in sorted(by_step.keys()):
        cell: dict[str, dict] = {}
        sub_records = by_step[step]
        for layer in LAYERS:
            tp_only = sum(1 for r in sub_records
                          if r.get("classification", {}).get(layer) == "TP")
            n = len(sub_records)
            recall = (tp_only / n) if n else 0.0
            cell[layer] = {"recall": recall, "n": n, "tp": tp_only}
        out[step] = cell
    return out


def build_table_per_subcategory(records: list[dict]) -> dict[str, dict[str, dict]]:
    """{subcategory: {layer: {recall, n}}}"""
    attacks = [r for r in records if r.get("label") == "attack"]
    by_sub: dict[str, list[dict]] = defaultdict(list)
    for r in attacks:
        sub = r.get("subcategory") or "unknown"
        by_sub[sub].append(r)
    out: dict[str, dict[str, dict]] = {}
    # Sort by count desc per spec
    for sub in sorted(by_sub.keys(), key=lambda s: -len(by_sub[s])):
        sub_recs = by_sub[sub]
        cell: dict[str, dict] = {}
        for layer in LAYERS:
            tp = sum(1 for r in sub_recs
                     if r.get("classification", {}).get(layer) == "TP")
            n = len(sub_recs)
            recall = (tp / n) if n else 0.0
            cell[layer] = {"recall": recall, "n": n, "tp": tp}
        out[sub] = cell
    return out


# ---------- rendering ----------


def _fmt_num(x: float, digits: int = 3) -> str:
    return f"{x:.{digits}f}"


def render_confusion_row(name: str, c: dict) -> str:
    return (
        f"| `{name}` | {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} | "
        f"{_fmt_num(c['precision'])} | {_fmt_num(c['recall'])} | "
        f"{_fmt_num(c['f1'])} | {_fmt_num(c['fpr'])} |"
    )


def render_table_overall(t: dict[str, dict]) -> str:
    lines = [
        "| layer | TP | FN | FP | TN | Precision | Recall | F1 | FPR |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for layer in LAYERS:
        lines.append(render_confusion_row(LAYER_LABELS[layer], t[layer]))
    return "\n".join(lines)


def render_table_per_family(t: dict[str, dict[str, dict]]) -> str:
    lines = [
        "| family | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for family in FAMILIES:
        first = True
        for layer in LAYERS:
            c = t[family][layer]
            lab = FAMILY_LABELS[family] if first else ""
            first = False
            lines.append(
                f"| {lab} | `{LAYER_LABELS[layer]}` | {c['tp']} | {c['fn']} | "
                f"{c['fp']} | {c['tn']} | {_fmt_num(c['precision'])} | "
                f"{_fmt_num(c['recall'])} | {_fmt_num(c['f1'])} | "
                f"{_fmt_num(c['fpr'])} |"
            )
    return "\n".join(lines)


def render_table_per_universe(t: dict[str, dict[str, dict]]) -> str:
    lines = [
        "| universe | layer | TP | FN | FP | TN | Prec | Recall | F1 | FPR |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for universe in ["real", "synthetic"]:
        first = True
        for layer in LAYERS:
            c = t[universe][layer]
            lab = universe if first else ""
            first = False
            lines.append(
                f"| {lab} | `{LAYER_LABELS[layer]}` | {c['tp']} | {c['fn']} | "
                f"{c['fp']} | {c['tn']} | {_fmt_num(c['precision'])} | "
                f"{_fmt_num(c['recall'])} | {_fmt_num(c['f1'])} | "
                f"{_fmt_num(c['fpr'])} |"
            )
    return "\n".join(lines)


def render_table_hardneg(t: dict[str, dict]) -> str:
    lines = [
        "| layer | handcrafted FP / total | template FP / total | "
        "Δpp (handcrafted − template) | overblock? |",
        "|---|---|---|---|---|",
    ]
    overblock_layers: list[str] = []
    for layer in LAYERS:
        cell = t[layer]
        hc_str = f"{cell['handcrafted_fp']} / {cell['handcrafted_total']}" + (
            f" ({cell['handcrafted_fp_rate']*100:.1f}%)"
            if cell["handcrafted_total"] else ""
        )
        tp_str = f"{cell['template_fp']} / {cell['template_total']}" + (
            f" ({cell['template_fp_rate']*100:.1f}%)"
            if cell["template_total"] else ""
        )
        gap = f"{cell['gap_pp']:+.1f} pp"
        flag = "**⚠ OVERBLOCK**" if cell["overblock_flag"] else "no"
        if cell["overblock_flag"]:
            overblock_layers.append(layer)
        lines.append(
            f"| `{LAYER_LABELS[layer]}` | {hc_str} | {tp_str} | {gap} | {flag} |"
        )
    body = "\n".join(lines)
    if overblock_layers:
        callout = (
            "\n\n> **⚠ Callout — Hard-neg overblock detected** on layer(s): "
            + ", ".join(f"`{LAYER_LABELS[l]}`" for l in overblock_layers)
            + f". Handcrafted FP rate exceeds template FP rate by ≥"
            + f"{HARD_NEG_OVERBLOCK_THRESHOLD_PP:.0f} percentage points. "
            "This indicates the system is over-sensitive to attack-shaped "
            "benigns. Inspect the handcrafted samples (search for "
            "`source=\"handcrafted\"` + `classification.<layer>=\"FP\"` in "
            "the merged JSONL) to audit which patterns are tripping."
        )
        return body + callout
    return body


def render_table_chain_step(t: dict[int, dict[str, dict]]) -> str:
    lines = [
        "| expected_block_step | n | layer | TP | Recall |",
        "|---|---|---|---|---|",
    ]
    if not t:
        return "_(no call_chain attacks present in the merged corpus)_"
    for step in sorted(t.keys()):
        first = True
        for layer in LAYERS:
            cell = t[step][layer]
            step_label = str(step) if first else ""
            n_label = str(cell["n"]) if first else ""
            first = False
            lines.append(
                f"| {step_label} | {n_label} | `{LAYER_LABELS[layer]}` | "
                f"{cell['tp']} | {_fmt_num(cell['recall'])} |"
            )
    return "\n".join(lines)


def render_table_per_subcategory(t: dict[str, dict[str, dict]]) -> str:
    lines = [
        "| subcategory | n | waf1_union recall | rag_on recall | dual recall |",
        "|---|---|---|---|---|",
    ]
    for sub, cells in t.items():
        n = cells[LAYERS[0]]["n"]
        row = [
            f"`{sub}`",
            str(n),
            _fmt_num(cells["waf1_union"]["recall"]),
            _fmt_num(cells["rag_on"]["recall"]),
            _fmt_num(cells["dual"]["recall"]),
        ]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def render_header(merged_path: Path, n_records: int) -> str:
    return f"""# M-Bench-Core Dual-Layer Evaluation Report

**Dataset**: M-Bench-Core (MCP-native attack benchmark)
**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Run git hash**: `{_git_hash()}`
**Source**: `{merged_path}`
**Total cases joined**: {n_records}

**Layers evaluated**:
- `waf1_union` = WAF1 strict (`checkRules`) ∪ WAF1 full (`validateToolCall`)
- `rag_on` = WAF2 LLM analysis with RAG knowledge enhancement
- `dual` = `waf1_union` ∪ `rag_on`
"""


def render_interpretation(
    overall: dict, family: dict, universe: dict, hardneg: dict, chain_step: dict
) -> str:
    parts: list[str] = []
    dual = overall["dual"]
    waf2 = overall["rag_on"]
    waf1 = overall["waf1_union"]

    parts.append(
        f"- **Overall (N={dual['n']})**: dual F1 = {_fmt_num(dual['f1'])}, "
        f"recall = {_fmt_num(dual['recall'])}, FPR = {_fmt_num(dual['fpr'])}. "
        f"WAF1-only F1 = {_fmt_num(waf1['f1'])}, WAF2-only F1 = "
        f"{_fmt_num(waf2['f1'])}. Dual gain over WAF2 alone: ΔF1 = "
        f"{(dual['f1'] - waf2['f1']):+.3f}."
    )

    # Per-family commentary
    for fam in FAMILIES:
        c_dual = family[fam]["dual"]
        c_waf1 = family[fam]["waf1_union"]
        c_waf2 = family[fam]["rag_on"]
        if c_dual["n"] == 0:
            continue
        winner_layer = max(
            LAYERS, key=lambda l: family[fam][l]["recall"]
        )
        parts.append(
            f"- **{FAMILY_LABELS[fam]}**: dual recall = "
            f"{_fmt_num(c_dual['recall'])} (TP={c_dual['tp']}/{c_dual['tp']+c_dual['fn']}). "
            f"Best layer: `{LAYER_LABELS[winner_layer]}` at recall "
            f"{_fmt_num(family[fam][winner_layer]['recall'])}."
        )

    # Universe gap commentary
    real_dual = universe["real"]["dual"]["recall"]
    syn_dual = universe["synthetic"]["dual"]["recall"]
    gap = (real_dual - syn_dual) * 100
    if abs(gap) >= 5:
        parts.append(
            f"- **Real vs synthetic gap** (dual): real recall = "
            f"{_fmt_num(real_dual)}, synthetic recall = "
            f"{_fmt_num(syn_dual)} (Δ = {gap:+.1f} pp). "
            "Synthetic tools may not be well-targeted by current rules — "
            "consider this when reading aggregated metrics."
        )

    # Chain block-step commentary
    if chain_step:
        early_steps = [s for s in chain_step if s == 1]
        late_steps = [s for s in chain_step if s >= 2]
        if early_steps and late_steps:
            early_recall = chain_step[1]["dual"]["recall"]
            late_recalls = [chain_step[s]["dual"]["recall"] for s in late_steps]
            avg_late = sum(late_recalls) / len(late_recalls)
            parts.append(
                f"- **Chain block-step**: step-1 (early) dual recall = "
                f"{_fmt_num(early_recall)}; step ≥2 (full-chain) average dual "
                f"recall = {_fmt_num(avg_late)}. "
                + (
                    "Chains that require seeing more steps are harder to catch."
                    if avg_late < early_recall - 0.05
                    else "Step depth has minor effect on catchability here."
                )
            )

    return "\n".join(parts)


def render_footer(merged_path: Path, n_records: int) -> str:
    return f"""## Reproduction

```bash
# Re-run merge
PYTHONPATH=. python3 -m waf2.rag.scripts.merge_mbench_layers \\
    --cases-dir <run-dir> \\
    --dataset-dir waf2/rag/eval/m-bench-core/ \\
    --out-dir <run-dir>

# Re-render this report
PYTHONPATH=. python3 -m waf2.rag.scripts.report_mbench \\
    --merged {merged_path} \\
    --out <run-dir>/dual-layer-mbench-report.md
```

- Joined cases: {n_records}
- Git hash: `{_git_hash()}`
- Generated: {datetime.now().isoformat()}
"""


def render_report(merged: list[dict], merged_path: Path) -> str:
    overall = build_table_overall(merged)
    per_family = build_table_per_family(merged)
    per_universe = build_table_per_universe(merged)
    hardneg = build_table_hardneg_breakdown(merged)
    chain_step = build_table_chain_block_step(merged)
    per_subcategory = build_table_per_subcategory(merged)

    sections = [
        render_header(merged_path, len(merged)),
        "",
        FAIRNESS_DISCLOSURES,
        "",
        "## Table 1 — Overall Confusion",
        "",
        "F1 uses **real precision** (M-Bench-Core has benigns; no precision=1 assumption).",
        "",
        render_table_overall(overall),
        "",
        "## Table 2 — Per-Family Confusion",
        "",
        "Each family's confusion counts that family's attacks + ALL benigns "
        "(stable FPR denominator across families).",
        "",
        render_table_per_family(per_family),
        "",
        "## Table 3 — Per-Tool-Universe (real vs synthetic)",
        "",
        f"Real tools: {sorted(REAL_SERVERS)}. Synthetic tools are any other "
        "`<server>` namespace (XML parsers, image processors, etc., introduced "
        "to cover attack categories absent from the real tool universe).",
        "",
        render_table_per_universe(per_universe),
        "",
        "## Table 4 — Hard-neg vs Template FP Breakdown",
        "",
        "Hard-neg benigns (`source=\"handcrafted\"`) are paired with attacks "
        "and intentionally use attack-shaped parameters with business-normal "
        "semantics. Template benigns (`source=\"template\"`) cover the "
        "stable business baseline.",
        "",
        render_table_hardneg(hardneg),
        "",
        "## Table 5 — Chain Block-Step Distribution",
        "",
        "Call-chain attacks grouped by `expected_block_step` (the latest step "
        "at which the system must block to count as TP).",
        "",
        render_table_chain_step(chain_step),
        "",
        "## Table 6 — Per-Subcategory Recall",
        "",
        "Sorted by sample count desc.",
        "",
        render_table_per_subcategory(per_subcategory),
        "",
        "## Interpretation",
        "",
        render_interpretation(overall, per_family, per_universe, hardneg, chain_step),
        "",
        render_footer(merged_path, len(merged)),
    ]
    return "\n".join(sections)


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--merged", required=True, help="path to cases-mbench-merged.jsonl")
    ap.add_argument(
        "--out", required=True,
        help="output path for dual-layer-mbench-report.md",
    )
    ap.add_argument(
        "--ablation-label",
        default="",
        help="label written to summary.tsv first column (e.g. 'WAF1-only', 'Full no-chain'). "
        "Defaults to the value found in merged JSONL records (or empty).",
    )
    ap.add_argument(
        "--append-to",
        default="",
        help="optional path to a cross-ablation index.tsv to append this run's summary row to",
    )
    args = ap.parse_args(argv)

    merged_path = Path(args.merged)
    if not merged_path.exists():
        print(f"merged file not found: {merged_path}", file=sys.stderr)
        return 2
    merged = load_merged(merged_path)
    if not merged:
        print("merged file is empty", file=sys.stderr)
        return 3

    report = render_report(merged, merged_path)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"[report-mbench] wrote {out_path}  ({len(merged)} cases)", file=sys.stderr)

    # Resolve ablation label: cli > first merged record's field > empty
    ablation_label = args.ablation_label or (merged[0].get("ablation_label") or "")
    metrics = compute_summary_metrics(merged)
    summary_path = write_summary_tsv(out_path.parent, ablation_label, metrics)
    print(
        f"[report-mbench] wrote {summary_path}  label={ablation_label!r}  "
        f"char_F1={metrics['char_F1']:.3f} pi_F1={metrics['pi_F1']:.3f} "
        f"chain_F1={metrics['chain_F1']:.3f} recall={metrics['recall']:.3f} "
        f"F1={metrics['F1']:.3f} "
        f"avgT_atk={metrics['avg_time_attacks_ms']:.1f}ms "
        f"avgT_ben={metrics['avg_time_benigns_ms']:.1f}ms",
        file=sys.stderr,
    )

    if args.append_to:
        index_path = Path(args.append_to)
        append_to_index(index_path, ablation_label, metrics)
        print(f"[report-mbench] appended to {index_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
