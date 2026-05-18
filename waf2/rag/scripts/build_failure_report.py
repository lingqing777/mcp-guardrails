"""Aggregate cases-*.jsonl + labels-*.jsonl into a fix-bucket ROI report.

For a given run directory (or explicit list of files), this script:

  1. Pairs each `cases-<dataset>-<round>.jsonl` with its sibling
     `labels-<dataset>-<round>.jsonl`.
  2. Aggregates labels by `fix_hint` → covered FN count, high-confidence
     proportion, breakdown per eval/split.
  3. Maps each `fix_hint` to a queued or unfiled OpenSpec change.
  4. Reads any `b1-sample-*.md` filled-in by the user to compute the B-1
     single-bucket hypothesis verdict (`intact` if ≥27/30 cases agree with
     `social_eng_no_marker`, `broken` otherwise).
  5. Emits `failure-analysis.md` with the per-bucket ROI table and overall
     `unknown` rate.

Usage:
    python3 waf2/rag/scripts/build_failure_report.py <run-dir>
    python3 waf2/rag/scripts/build_failure_report.py <run-dir> -o report.md
    python3 waf2/rag/scripts/build_failure_report.py <run-dir> --compare <prior-run-dir>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

# fix_hint → (queued change, status)
FIX_TO_CHANGE = {
    "fath_judge_wrap": ("harden-waf2-llm-judge-field-isolation", "queued"),
    "kb_inject_socialeng": ("inject-socialeng-kb-samples", "unfiled"),
    "field_path_boost": ("add-field-path-aware-scoring", "unfiled"),
    "depth_limit_bump": ("harden-waf2-nested-json-extraction", "archived"),
    "new_decoder": ("(per-encoding change)", "unfiled"),
    "kb_clean": ("(KB curation sub-task)", "unfiled"),
    "route_threshold_tune": ("evaluate-waf2-rag-react-routing-and-models", "in-progress"),
    "category_rule_refine": ("(local_attack_score refinement)", "unfiled"),
    "react_prompt_robustness": ("(ReAct prompt / parser robustness)", "unfiled"),
    "manual_review_required": ("(unknown; needs rule expansion)", "out-of-scope"),
    "(none, monitored)": ("harden-waf2-react-fallback-rag-rescue (this)", "shipped"),
}

UNKNOWN_RATE_WARNING = 0.30
B1_SINGLE_BUCKET_CAUSE = "social_eng_no_marker"
B1_HYPOTHESIS_BREAK_THRESHOLD = 3


def _load_jsonl(path: Path) -> list[dict]:
    out = []
    for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{ln}: invalid JSON ({exc})")
    return out


def _split_fix(fix_hint: str) -> list[str]:
    if not fix_hint:
        return ["(blank)"]
    return [p.strip() for p in fix_hint.split("+") if p.strip()]


def _discover_pairs(run_dir: Path) -> list[tuple[Path, Path | None]]:
    pairs = []
    for cases_path in sorted(run_dir.glob("cases-*.jsonl")):
        label_path = cases_path.with_name(cases_path.name.replace("cases-", "labels-", 1))
        pairs.append((cases_path, label_path if label_path.is_file() else None))
    return pairs


def _aggregate(
    pairs: list[tuple[Path, Path | None]],
) -> dict:
    fix_counts: Counter = Counter()
    fix_high_conf: Counter = Counter()
    fix_by_source: dict[str, Counter] = {}
    layer_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    record_kind_counts: Counter = Counter()
    unlabeled_files: list[str] = []
    per_source: list[dict] = []
    total_cases = 0
    total_unknown = 0
    case_ids_by_source: dict[str, set[str]] = {}

    for cases_path, label_path in pairs:
        cases = _load_jsonl(cases_path)
        source = cases_path.stem.replace("cases-", "")
        total_cases += len(cases)
        case_ids_by_source[source] = {c.get("case_id", "") for c in cases}
        if label_path is None:
            unlabeled_files.append(cases_path.name)
            per_source.append(
                {"source": source, "n": len(cases), "unknown": "?", "labeled": False}
            )
            continue
        labels = _load_jsonl(label_path)
        labels_by_id = {l.get("case_id", ""): l for l in labels}
        source_unknown = 0
        for case in cases:
            rk = case.get("record_kind", "")
            record_kind_counts[rk] += 1
            label = labels_by_id.get(case.get("case_id", ""))
            if not label:
                source_unknown += 1
                continue
            layer = label.get("layer", "unknown")
            rule_id = label.get("rule_id", "R?")
            confidence = label.get("confidence", "low")
            fix_hint = label.get("fix_hint", "")
            layer_counts[layer] += 1
            rule_counts[rule_id] += 1
            if layer == "unknown":
                source_unknown += 1
            for fix in _split_fix(fix_hint):
                fix_counts[fix] += 1
                if confidence == "high":
                    fix_high_conf[fix] += 1
                fix_by_source.setdefault(fix, Counter())[source] += 1
        total_unknown += source_unknown
        per_source.append(
            {
                "source": source,
                "n": len(cases),
                "unknown": source_unknown,
                "labeled": True,
            }
        )

    return {
        "total_cases": total_cases,
        "total_unknown": total_unknown,
        "fix_counts": fix_counts,
        "fix_high_conf": fix_high_conf,
        "fix_by_source": fix_by_source,
        "layer_counts": layer_counts,
        "rule_counts": rule_counts,
        "record_kind_counts": record_kind_counts,
        "unlabeled_files": unlabeled_files,
        "per_source": per_source,
        "case_ids_by_source": case_ids_by_source,
    }


# B-1 sample markdown is parsed with a forgiving regex that recovers
# `case_id` and the cause filled into the `cause:` token. Cases still
# showing the literal `__________` are treated as not-yet-labeled.
_CASE_LINE = re.compile(
    r"\*\*case_id:\*\*\s*`([^`]+)`.*?\*\*cause:\*\*\s*`([^`]+)`",
    re.IGNORECASE,
)


def _parse_b1_sample(md_path: Path) -> dict:
    text = md_path.read_text(encoding="utf-8")
    filled: dict[str, str] = {}
    blanks: list[str] = []
    for cid, cause in _CASE_LINE.findall(text):
        cause = cause.strip()
        if cause in ("", "__________"):
            blanks.append(cid)
        else:
            filled[cid] = cause
    return {"filled": filled, "blanks": blanks, "total": len(filled) + len(blanks)}


def _b1_hypothesis_verdict(filled: dict[str, str]) -> tuple[str, dict[str, int]]:
    counts = Counter(filled.values())
    non_dominant = sum(n for c, n in counts.items() if c != B1_SINGLE_BUCKET_CAUSE)
    if not filled:
        verdict = "no-data"
    elif non_dominant >= B1_HYPOTHESIS_BREAK_THRESHOLD:
        verdict = "broken"
    else:
        verdict = "intact"
    return verdict, dict(counts)


def _format_report(
    run_dir: Path,
    agg: dict,
    b1_sample: dict | None,
    compare_diff: dict | None,
) -> str:
    lines: list[str] = []
    lines.append(f"# Failure Analysis Report — {run_dir.name}")
    lines.append("")

    # Overview
    total = agg["total_cases"]
    unknown = agg["total_unknown"]
    unknown_rate = (unknown / total) if total else 0.0
    lines.append("## Overview")
    lines.append("")
    lines.append(f"- total cases (FN + FP + miscategorized + ambiguous): **{total}**")
    lines.append(
        f"- unmatched (rule_id=R8 unknown): **{unknown}** "
        f"({unknown_rate:.1%})"
    )
    # harden-waf2-react-fallback-rag-rescue: surface R10 (rescued) count
    # separately so reports can show how many R9-style failures this change
    # converted into successful blocks. R10 cases are also counted in the
    # `(none, monitored)` fix bucket below.
    rescued_count = agg["rule_counts"].get("R10", 0)
    if rescued_count > 0:
        r9_count = agg["rule_counts"].get("R9", 0)
        denom = r9_count + rescued_count
        ratio = (rescued_count / denom * 100) if denom else 0.0
        lines.append(
            f"- rescued by `harden-waf2-react-fallback-rag-rescue`: **{rescued_count}** "
            f"(R10; previously would have been R9 = {r9_count}, rescue ratio "
            f"{ratio:.1f}%)"
        )
    if unknown_rate > UNKNOWN_RATE_WARNING:
        lines.append(
            f"- ⚠️ unknown rate exceeds {UNKNOWN_RATE_WARNING:.0%} — "
            "consider extending R1-R7 or expanding manual sampling."
        )
    if agg["unlabeled_files"]:
        lines.append("- ⚠️ unlabeled (no labels-*.jsonl sibling):")
        for n in agg["unlabeled_files"]:
            lines.append(f"  - `{n}`")
    lines.append("")
    lines.append("### Per-source")
    lines.append("")
    lines.append("| source | cases | unknown | labeled |")
    lines.append("|---|---:|---:|:---:|")
    for s in agg["per_source"]:
        lines.append(
            f"| `{s['source']}` | {s['n']} | {s['unknown']} | "
            f"{'✓' if s['labeled'] else '—'} |"
        )
    lines.append("")

    # Fix bucket ROI
    lines.append("## Fix-bucket ROI")
    lines.append("")
    lines.append(
        "Counts are number of cases whose `fix_hint` mentions the bucket. "
        "Composite hints (e.g. `fath_judge_wrap+field_path_boost`) contribute "
        "to every named bucket."
    )
    lines.append("")
    lines.append("| fix_hint | covered | high-conf | maps_to | status |")
    lines.append("|---|---:|---:|---|---|")
    for fix, n in agg["fix_counts"].most_common():
        change_name, status = FIX_TO_CHANGE.get(fix, ("(unmapped)", "—"))
        high = agg["fix_high_conf"].get(fix, 0)
        lines.append(
            f"| `{fix}` | {n} | {high} | `{change_name}` | {status} |"
        )
    lines.append("")
    lines.append("### Breakdown by source (top fix buckets only)")
    lines.append("")
    for fix, _ in agg["fix_counts"].most_common(5):
        per_src = agg["fix_by_source"].get(fix, Counter())
        if not per_src:
            continue
        srcs = ", ".join(f"{s}: {n}" for s, n in per_src.most_common())
        lines.append(f"- `{fix}`: {srcs}")
    lines.append("")

    # Layer / rule distribution
    lines.append("## Layer distribution")
    lines.append("")
    lines.append("| layer | count |")
    lines.append("|---|---:|")
    for layer, n in agg["layer_counts"].most_common():
        lines.append(f"| {layer} | {n} |")
    lines.append("")
    lines.append("## Rule fire counts")
    lines.append("")
    lines.append("| rule_id | count |")
    lines.append("|---|---:|")
    for rid, n in sorted(agg["rule_counts"].items()):
        lines.append(f"| {rid} | {n} |")
    lines.append("")

    # B-1 single-bucket verdict
    if b1_sample is not None:
        lines.append("## B-1 single-bucket hypothesis")
        lines.append("")
        filled = b1_sample["filled"]
        blanks = b1_sample["blanks"]
        total_sample = b1_sample["total"]
        verdict, counts = _b1_hypothesis_verdict(filled)
        lines.append(f"- sample size: **{total_sample}** ({len(blanks)} blank)")
        lines.append(
            f"- dominant-bucket count: **{counts.get(B1_SINGLE_BUCKET_CAUSE, 0)}** "
            f"(target: `{B1_SINGLE_BUCKET_CAUSE}`)"
        )
        non_dominant = sum(n for c, n in counts.items() if c != B1_SINGLE_BUCKET_CAUSE)
        lines.append(f"- non-dominant: **{non_dominant}**")
        lines.append(f"- verdict: **{verdict}**")
        if verdict == "broken":
            lines.append(
                f"  - ≥ {B1_HYPOTHESIS_BREAK_THRESHOLD} cases disagree with the dominant bucket. "
                "Recommend extending sample to 100 and re-checking."
            )
        if counts:
            lines.append("")
            lines.append("### Cause distribution in sample")
            lines.append("")
            lines.append("| cause | count |")
            lines.append("|---|---:|")
            for cause, n in Counter(counts).most_common():
                lines.append(f"| `{cause}` | {n} |")
        lines.append("")

    # Cross-run diff
    if compare_diff is not None:
        lines.append("## Cross-run diff")
        lines.append("")
        lines.append(f"Compared against: `{compare_diff['prior_dir']}`")
        lines.append("")
        lines.append(
            f"- newly recorded cases: **{compare_diff['new']}** "
            "(present here, absent prior)"
        )
        lines.append(
            f"- fixed cases: **{compare_diff['fixed']}** "
            "(present prior, absent here)"
        )
        lines.append(f"- persistent cases: **{compare_diff['same']}**")
        lines.append("")

    return "\n".join(lines) + "\n"


def _compare(this_ids: dict[str, set[str]], prior_dir: Path) -> dict:
    prior_pairs = _discover_pairs(prior_dir)
    prior_ids: set[str] = set()
    for cases_path, _ in prior_pairs:
        for case in _load_jsonl(cases_path):
            prior_ids.add(case.get("case_id", ""))
    this_ids_flat: set[str] = set()
    for ids in this_ids.values():
        this_ids_flat.update(ids)
    new = this_ids_flat - prior_ids
    fixed = prior_ids - this_ids_flat
    same = this_ids_flat & prior_ids
    return {
        "prior_dir": str(prior_dir),
        "new": len(new),
        "fixed": len(fixed),
        "same": len(same),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate per-case labels into a fix-bucket ROI report.")
    parser.add_argument("run_dir", help="Directory containing cases-*.jsonl and labels-*.jsonl")
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output markdown path. Default: <run_dir>/failure-analysis.md",
    )
    parser.add_argument(
        "--compare",
        default=None,
        help="Prior run directory for cross-run diff (counts new vs fixed cases by case_id).",
    )
    parser.add_argument(
        "--b1-sample",
        default=None,
        help="Path to b1-sample-*.md filled in by the user (default: auto-detect "
        "in run_dir).",
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 2

    pairs = _discover_pairs(run_dir)
    if not pairs:
        print(f"no cases-*.jsonl in {run_dir}", file=sys.stderr)
        return 1

    agg = _aggregate(pairs)

    # Locate B-1 sample markdown if any
    b1_sample = None
    sample_md = (
        Path(args.b1_sample)
        if args.b1_sample
        else next(iter(sorted(run_dir.glob("b1-sample-*.md"))), None)
    )
    if sample_md and sample_md.is_file():
        b1_sample = _parse_b1_sample(sample_md)

    compare_diff = None
    if args.compare:
        compare_diff = _compare(agg["case_ids_by_source"], Path(args.compare))

    report = _format_report(run_dir, agg, b1_sample, compare_diff)
    out = Path(args.output) if args.output else run_dir / "failure-analysis.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"📄 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
