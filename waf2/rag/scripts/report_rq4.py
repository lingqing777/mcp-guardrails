"""RQ4: Comparison report generator.

Reads cases-rq4-{dataset}-{config}.jsonl files from a run directory and
generates a markdown report comparing No-RAG / Generic-RAG / MCP-RAG.

Usage:
    PYTHONPATH=. python3 -m waf2.rag.scripts.report_rq4 \\
        --run-dir waf2/rag/eval/runs/<date>-rq4/ \\
        --out waf2/rag/eval/runs/<date>-rq4/rq4-report.md
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------- constants ----------

DATASETS = ["mbench", "pi-eval", "adversarial"]
CONFIGS = ["rag-off", "rag-generic", "rag-mcp"]

DATASET_LABELS = {
    "mbench": "M-Bench",
    "pi-eval": "PI-Eval",
    "adversarial": "Adversarial",
}

CONFIG_LABELS = {
    "rag-off": "rag-off",
    "rag-generic": "rag-generic",
    "rag-mcp": "rag-mcp",
}

# Gray-area definitions (mirrors run_rq4.py)
GRAY_AREA_SUBCATEGORIES = {
    "indirect_prompt_injection",
    "indirect_pi",
    "context_manipulation",
    "encoded_injection",
}

GRAY_AREA_TAGS = {
    "pi-indirect-mcp",
    "pi-academic-pretense",
    "pi-translate-cover",
    "pi-bracket-redirect",
    "pi-llama-sys-tag",
    "pi-pig-latin-leak",
    "pi-fictional-persona",
    "benign-discuss-sqli",
    "benign-ignore-context",
    "benign-edu-xss",
    "benign-discuss-IFS",
    "benign-user-config",
}


# ---------- IO ----------


def load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file into a list of dicts."""
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def load_cases(run_dir: Path, dataset: str, config: str) -> list[dict]:
    """Read one cases-rq4-{dataset}-{config}.jsonl file."""
    path = run_dir / f"cases-rq4-{dataset}-{config}.jsonl"
    if not path.exists():
        print(f"  [warn] missing: {path}", file=sys.stderr)
        return []
    return load_jsonl(path)


# ---------- metrics ----------


def compute_metrics(records: list[dict]) -> dict[str, Any]:
    """Compute TP/FN/FP/TN/precision/recall/F1/FPR/avg_latency/rag_hit_rate."""
    tp = fn = fp = tn = 0
    latencies: list[float] = []
    rag_used_count = 0

    for rec in records:
        outcome = rec.get("outcome", "")
        label = rec.get("label", "")
        is_blocked = outcome == "blocked"
        is_attack = label == "attack"

        if is_blocked and is_attack:
            tp += 1
        elif not is_blocked and is_attack:
            fn += 1
        elif is_blocked and not is_attack:
            fp += 1
        else:
            tn += 1

        latencies.append(float(rec.get("latency_ms", 0) or 0))
        if rec.get("rag_used", False):
            rag_used_count += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0
    rag_hit_rate = (rag_used_count / len(records) * 100) if records else 0.0

    return {
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "avg_latency": avg_latency,
        "rag_hit_rate": rag_hit_rate,
        "n": len(records),
    }


def _is_gray_area(record: dict, dataset: str) -> bool:
    """Determine if a record is a gray-area sample based on dataset-specific rules."""
    label = record.get("label", "")
    subcat = record.get("subcategory", "")
    tag = record.get("tag", "")

    if dataset == "mbench":
        if label == "attack" and subcat == "indirect_pi":
            return True
        if label == "benign" and tag.startswith("benign-"):
            # handcrafted benigns in M-Bench are gray-area; we approximate
            # via is_gray_area field if present, otherwise check tag
            pass
        return record.get("is_gray_area", False)
    if dataset == "pi-eval":
        return subcat in GRAY_AREA_SUBCATEGORIES
    if dataset == "adversarial":
        return tag in GRAY_AREA_TAGS
    return False


def compute_gray_area_metrics(
    records: list[dict], dataset: str
) -> dict[str, dict[str, Any]]:
    """Compute gray-area metrics split by attacks and benigns.

    Returns:
        {"attacks": {...metrics...}, "benigns": {...metrics...}}
    """
    gray_attacks = [
        r for r in records
        if r.get("label") == "attack" and r.get("is_gray_area", False)
    ]
    gray_benigns = [
        r for r in records
        if r.get("label") == "benign" and r.get("is_gray_area", False)
    ]

    result: dict[str, dict[str, Any]] = {}

    # Attack-side: only TP/FN are meaningful
    if gray_attacks:
        tp = sum(1 for r in gray_attacks if r["outcome"] == "blocked")
        fn = len(gray_attacks) - tp
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        result["attacks"] = {
            "n": len(gray_attacks),
            "tp": tp,
            "fn": fn,
            "fp": 0,
            "tn": 0,
            "recall": recall,
            "precision": 0.0,
            "f1": 0.0,
            "fpr": 0.0,
        }
    else:
        result["attacks"] = {
            "n": 0, "tp": 0, "fn": 0, "fp": 0, "tn": 0,
            "recall": 0.0, "precision": 0.0, "f1": 0.0, "fpr": 0.0,
        }

    # Benign-side: only FP/TN are meaningful
    if gray_benigns:
        fp = sum(1 for r in gray_benigns if r["outcome"] == "blocked")
        tn = len(gray_benigns) - fp
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        result["benigns"] = {
            "n": len(gray_benigns),
            "tp": 0,
            "fn": 0,
            "fp": fp,
            "tn": tn,
            "recall": 0.0,
            "precision": 0.0,
            "f1": 0.0,
            "fpr": fpr,
        }
    else:
        result["benigns"] = {
            "n": 0, "tp": 0, "fn": 0, "fp": 0, "tn": 0,
            "recall": 0.0, "precision": 0.0, "f1": 0.0, "fpr": 0.0,
        }

    return result


def _gray_area_subset_label(dataset: str, side: str) -> str:
    """Return a human-readable label for the gray-area subset."""
    if dataset == "mbench":
        if side == "attacks":
            return "attacks (indirect_pi)"
        return "benigns (handcrafted)"
    if dataset == "pi-eval":
        if side == "attacks":
            return "gray-area attacks"
        return "gray-area benigns"
    if dataset == "adversarial":
        if side == "attacks":
            return "gray-area attacks"
        return "gray-area benigns"
    return f"{side}"


# ---------- subcategory breakdown ----------


def compute_per_subcategory(records: list[dict]) -> dict[str, dict[str, dict[str, Any]]]:
    """M-Bench only: {subcategory: {config: {recall, n, tp}}}."""
    by_subcat: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        subcat = rec.get("subcategory", "") or "unknown"
        by_subcat[subcat].append(rec)

    out: dict[str, dict[str, dict[str, Any]]] = {}
    for subcat in sorted(by_subcat.keys(), key=lambda s: -len(by_subcat[s])):
        sub_records = by_subcat[subcat]
        tp = sum(1 for r in sub_records if r["outcome"] == "blocked")
        n = len(sub_records)
        recall = tp / n if n else 0.0
        out[subcat] = {
            "recall": recall,
            "n": n,
            "tp": tp,
        }
    return out


# ---------- formatting helpers ----------


def _f(x: float, digits: int = 3) -> str:
    """Format a float to the given number of decimal places."""
    return f"{x:.{digits}f}"


def _pct(x: float) -> str:
    """Format a percentage with one decimal place."""
    return f"{x:.1f}"


# ---------- rendering ----------


def render_table_overall(all_data: dict[str, dict[str, list[dict]]]) -> str:
    """Render Table 1 -- Overall Comparison."""
    lines = [
        "## Table 1 -- Overall Comparison",
        "",
        "| Dataset | Config | N_atk | N_ben | TP | FN | FP | TN | "
        "Recall | Precision | F1 | FPR | Avg LLM (ms) | RAG Hit% |",
        "|---------|--------|-------|-------|----|----|----|----|"
        "--------|-----------|----|-----|-------------|----------|",
    ]

    for dataset in DATASETS:
        if dataset not in all_data:
            continue
        for config in CONFIGS:
            records = all_data[dataset].get(config, [])
            if not records:
                continue

            n_atk = sum(1 for r in records if r.get("label") == "attack")
            n_ben = sum(1 for r in records if r.get("label") == "benign")
            m = compute_metrics(records)

            has_benigns = n_ben > 0

            fp_str = str(m["fp"]) if has_benigns else "---"
            tn_str = str(m["tn"]) if has_benigns else "---"
            fpr_str = _f(m["fpr"]) if has_benigns else "---"
            precision_str = _f(m["precision"]) if has_benigns else "---"
            f1_str = _f(m["f1"]) if has_benigns else "---"

            # For attack-only datasets, precision is not meaningful;
            # but recall is always meaningful.
            if not has_benigns:
                precision_str = "---"
                f1_str = "---"

            lines.append(
                f"| {DATASET_LABELS[dataset]} | {config} | "
                f"{n_atk} | {n_ben} | "
                f"{m['tp']} | {m['fn']} | {fp_str} | {tn_str} | "
                f"{_f(m['recall'])} | {precision_str} | {f1_str} | {fpr_str} | "
                f"{_pct(m['avg_latency'])} | {_pct(m['rag_hit_rate'])} |"
            )

    return "\n".join(lines)


def render_table_gray_area(all_data: dict[str, dict[str, list[dict]]]) -> str:
    """Render Table 2 -- Gray-Area Analysis."""
    lines = [
        "## Table 2 -- Gray-Area Analysis",
        "",
        "| Dataset | Gray Subset | N | Config | TP | FN | FP | TN | "
        "Recall | F1 | FPR |",
        "|---------|------------|---|--------|----|----|----|----|"
        "--------|----|-----|",
    ]

    for dataset in DATASETS:
        if dataset not in all_data:
            continue
        for config in CONFIGS:
            records = all_data[dataset].get(config, [])
            if not records:
                continue

            ga = compute_gray_area_metrics(records, dataset)

            # Attack-side gray area
            atk = ga["attacks"]
            if atk["n"] > 0:
                subset_label = _gray_area_subset_label(dataset, "attacks")
                lines.append(
                    f"| {DATASET_LABELS[dataset]} | {subset_label} | "
                    f"{atk['n']} | {config} | "
                    f"{atk['tp']} | {atk['fn']} | --- | --- | "
                    f"{_f(atk['recall'])} | --- | --- |"
                )

            # Benign-side gray area
            ben = ga["benigns"]
            if ben["n"] > 0:
                subset_label = _gray_area_subset_label(dataset, "benigns")
                lines.append(
                    f"| {DATASET_LABELS[dataset]} | {subset_label} | "
                    f"{ben['n']} | {config} | "
                    f"--- | --- | {ben['fp']} | {ben['tn']} | "
                    f"--- | --- | {_f(ben['fpr'])} |"
                )

    return "\n".join(lines)


def render_table_per_subcategory(
    mbench_data: dict[str, list[dict]],
) -> str:
    """Render Table 3 -- Per-Subcategory Recall (M-Bench-Core)."""
    # Collect all subcategories across configs
    all_subcats: dict[str, dict[str, dict[str, Any]]] = {}
    for config in CONFIGS:
        records = mbench_data.get(config, [])
        if not records:
            continue
        by_sub = compute_per_subcategory(records)
        for subcat, info in by_sub.items():
            if subcat not in all_subcats:
                all_subcats[subcat] = {}
            all_subcats[subcat][config] = info

    # Sort by total count descending
    def _total_n(subcat: str) -> int:
        return sum(v["n"] for v in all_subcats[subcat].values())

    sorted_subcats = sorted(all_subcats.keys(), key=lambda s: -_total_n(s))

    lines = [
        "## Table 3 -- Per-Subcategory Recall (M-Bench-Core)",
        "",
        "| Subcategory | N | rag-off recall | rag-generic recall | rag-mcp recall |",
        "|-------------|---|---------------|-------------------|---------------|",
    ]

    for subcat in sorted_subcats:
        configs_info = all_subcats[subcat]
        # Use the first config's n as representative (they should all have the
        # same n for the same subcategory)
        n = 0
        for cfg in CONFIGS:
            if cfg in configs_info:
                n = configs_info[cfg]["n"]
                break

        recall_cells: list[str] = []
        for cfg in CONFIGS:
            if cfg in configs_info:
                recall_cells.append(_f(configs_info[cfg]["recall"]))
            else:
                recall_cells.append("---")

        lines.append(
            f"| `{subcat}` | {n} | "
            + " | ".join(recall_cells)
            + " |"
        )

    return "\n".join(lines)


def render_interpretation(all_data: dict[str, dict[str, list[dict]]]) -> str:
    """Generate auto-commentary on the results."""
    parts: list[str] = [
        "## Interpretation",
        "",
    ]

    # Best config per dataset by F1
    parts.append("### Best Config per Dataset (by F1)")
    parts.append("")
    for dataset in DATASETS:
        if dataset not in all_data:
            continue
        best_cfg = None
        best_f1 = -1.0
        for config in CONFIGS:
            records = all_data[dataset].get(config, [])
            if not records:
                continue
            m = compute_metrics(records)
            # For attack-only datasets, use recall as proxy (F1 not meaningful)
            has_benigns = sum(1 for r in records if r.get("label") == "benign") > 0
            score = m["f1"] if has_benigns else m["recall"]
            if score > best_f1:
                best_f1 = score
                best_cfg = config

        if best_cfg is not None:
            has_benigns = any(
                r.get("label") == "benign"
                for r in all_data[dataset].get(best_cfg, [])
            )
            metric_name = "F1" if has_benigns else "Recall"
            parts.append(
                f"- **{DATASET_LABELS[dataset]}**: `{best_cfg}` "
                f"(best {metric_name} = {_f(best_f1)})"
            )
    parts.append("")

    # Gray-area F1 differences
    parts.append("### Gray-Area Analysis")
    parts.append("")
    for dataset in DATASETS:
        if dataset not in all_data:
            continue

        # Collect gray-area attack recall per config
        atk_recalls: dict[str, float] = {}
        ben_fprs: dict[str, float] = {}
        for config in CONFIGS:
            records = all_data[dataset].get(config, [])
            if not records:
                continue
            ga = compute_gray_area_metrics(records, dataset)
            if ga["attacks"]["n"] > 0:
                atk_recalls[config] = ga["attacks"]["recall"]
            if ga["benigns"]["n"] > 0:
                ben_fprs[config] = ga["benigns"]["fpr"]

        if atk_recalls:
            best_atk = max(atk_recalls, key=lambda c: atk_recalls[c])
            worst_atk = min(atk_recalls, key=lambda c: atk_recalls[c])
            delta = atk_recalls[best_atk] - atk_recalls[worst_atk]
            parts.append(
                f"- **{DATASET_LABELS[dataset]} gray-area attacks**: "
                f"best recall = `{best_atk}` ({_f(atk_recalls[best_atk])}), "
                f"worst = `{worst_atk}` ({_f(atk_recalls[worst_atk])}), "
                f"delta = {_f(delta)}"
            )
        if ben_fprs:
            best_ben = min(ben_fprs, key=lambda c: ben_fprs[c])
            worst_ben = max(ben_fprs, key=lambda c: ben_fprs[c])
            delta = ben_fprs[worst_ben] - ben_fprs[best_ben]
            parts.append(
                f"- **{DATASET_LABELS[dataset]} gray-area benigns**: "
                f"best FPR = `{best_ben}` ({_f(ben_fprs[best_ben])}), "
                f"worst = `{worst_ben}` ({_f(ben_fprs[worst_ben])}), "
                f"delta = {_f(delta)}"
            )
    parts.append("")

    # RAG hit rate comparison
    parts.append("### RAG Hit Rate")
    parts.append("")
    for dataset in DATASETS:
        if dataset not in all_data:
            continue
        rates: list[str] = []
        for config in CONFIGS:
            records = all_data[dataset].get(config, [])
            if not records:
                continue
            m = compute_metrics(records)
            rates.append(f"`{config}` = {_pct(m['rag_hit_rate'])}%")
        if rates:
            parts.append(f"- **{DATASET_LABELS[dataset]}**: {', '.join(rates)}")
    parts.append("")

    # Latency comparison
    parts.append("### Latency Comparison")
    parts.append("")
    for dataset in DATASETS:
        if dataset not in all_data:
            continue
        lats: list[str] = []
        for config in CONFIGS:
            records = all_data[dataset].get(config, [])
            if not records:
                continue
            m = compute_metrics(records)
            lats.append(f"`{config}` = {_pct(m['avg_latency'])}ms")
        if lats:
            parts.append(f"- **{DATASET_LABELS[dataset]}**: {', '.join(lats)}")

    return "\n".join(parts)


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="RQ4: Comparison report generator for RAG domain filter evaluation."
    )
    ap.add_argument(
        "--run-dir",
        required=True,
        help="directory containing cases-rq4-{dataset}-{config}.jsonl files",
    )
    ap.add_argument(
        "--out",
        required=True,
        help="output path for rq4-report.md",
    )
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"run directory not found: {run_dir}", file=sys.stderr)
        return 2

    # Load all 9 JSONL files
    all_data: dict[str, dict[str, list[dict]]] = {}
    total_loaded = 0
    for dataset in DATASETS:
        all_data[dataset] = {}
        for config in CONFIGS:
            records = load_cases(run_dir, dataset, config)
            all_data[dataset][config] = records
            total_loaded += len(records)

    if total_loaded == 0:
        print("no records found in any JSONL file", file=sys.stderr)
        return 3

    print(f"[report-rq4] loaded {total_loaded} records from {run_dir}", file=sys.stderr)

    # Build the report
    sections = [
        f"# RQ4: RAG Domain Filter Evaluation Report",
        "",
        f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Run directory**: `{run_dir}`",
        "",
        render_table_overall(all_data),
        "",
        render_table_gray_area(all_data),
        "",
        render_table_per_subcategory(all_data.get("mbench", {})),
        "",
        render_interpretation(all_data),
        "",
    ]

    report = "\n".join(sections)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"[report-rq4] wrote {out_path}  ({total_loaded} records)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
