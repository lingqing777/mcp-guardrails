"""Sample a markdown checklist for manual cause labeling.

For high-volume datasets (B-1, ~380 FN) we trust the auto-derived rules on
the full set but pull a deterministic sample (default 30) for human spot-check
to validate the dominant bucket hypothesis. For small datasets (B-0, CSIC) the
full FN/FP/miscategorized list is emitted (no sampling).

The output is a markdown checklist. Each item shows case_id, auto-derived
layer/rule_id, and a blank `cause: __________` field for the user to fill in.

Filled-in markdown is later consumed by `build_failure_report.py` to compute
the B-1 single-bucket verdict (`intact` vs `broken`).

Usage:
    python3 waf2/rag/scripts/sample_for_manual.py <cases.jsonl> \\
        [--eval (csic|b0|b1)] [--n 30] \\
        [--labels labels.jsonl] [-o output.md]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

SAMPLE_SEED = "waf2-eval-fal-2026-05-17"
DEFAULT_B1_SAMPLE = 30
DEFAULT_TRUNCATE = 200


def _infer_eval(cases: list[dict]) -> str:
    datasets = {c.get("dataset", "") for c in cases}
    if datasets == {"csic"}:
        return "csic"
    if datasets == {"b0"}:
        return "b0"
    if datasets == {"b1"}:
        return "b1"
    # Fallback: pick whatever dominates
    if not datasets:
        return "unknown"
    return next(iter(datasets))


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


def _truncate(s: str, limit: int = DEFAULT_TRUNCATE) -> str:
    if len(s) <= limit:
        return s
    return s[: limit - 3] + "..."


def select(cases: list[dict], eval_name: str, n: int) -> list[dict]:
    """B-1 → sample n (deterministic). B-0/CSIC → return all in original order."""
    if eval_name == "b1" and 0 < n < len(cases):
        rnd = random.Random(SAMPLE_SEED)
        idxs = sorted(rnd.sample(range(len(cases)), n))
        return [cases[i] for i in idxs]
    return list(cases)


def build_checklist(
    cases: list[dict],
    labels_by_id: dict[str, dict],
    eval_name: str,
    *,
    full_size: int,
) -> str:
    lines: list[str] = []
    lines.append(f"# Manual cause labeling — eval={eval_name}")
    lines.append("")
    lines.append(f"- total cases in input: **{full_size}**")
    lines.append(f"- sampled here: **{len(cases)}**")
    lines.append(
        f"- sampling seed: `{SAMPLE_SEED}` (deterministic; same input + count → same selection)"
        if eval_name == "b1" and len(cases) < full_size
        else "- sampling: **none** (full enumeration)"
    )
    lines.append("")
    lines.append(
        "Fill the `cause:` blank for each item. Suggested vocabulary:\n"
        "`social_eng_no_marker` `carrier_unaware` `deep_nesting` `novel_encoding` "
        "`kb_coverage_gap` `kb_label_noise` `threshold_misfit` `ambiguous_pattern` "
        "`other` (with note)."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    for case in cases:
        case_id = case.get("case_id", "")
        body = case.get("body", "")
        record_kind = case.get("record_kind", "")
        score = case.get("local_score_total", 0.0)
        rag = case.get("rag_top_score", 0.0)
        route = case.get("route", "")
        label = labels_by_id.get(case_id, {})
        rule_id = label.get("rule_id", "?")
        layer = label.get("layer", "?")
        meta_bits = [
            f"kind={record_kind}",
            f"score={score:.2f}",
            f"rag={rag:.2f}",
            f"route={route}",
        ]
        # B-0 / B-1 extras
        sub = case.get("subcategory")
        wrap = case.get("wrap")
        if sub or wrap:
            meta_bits.append(f"sub={sub or ''}/wrap={wrap or ''}")
        split = case.get("split")
        atk = case.get("attack_type")
        if split or atk:
            meta_bits.append(f"split={split or ''}/atk={atk or ''}")
        meta = " · ".join(meta_bits)
        lines.append(f"- [ ] **case_id:** `{case_id}` | **auto:** {rule_id}/{layer} | **cause:** `__________`")
        lines.append(f"      _{meta}_")
        lines.append(f"      `body:` `{_truncate(body)}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a markdown checklist for manual cause labeling.")
    parser.add_argument("cases", help="cases-*.jsonl file")
    parser.add_argument(
        "--eval",
        choices=("csic", "b0", "b1", "auto"),
        default="auto",
        help="Which sampling strategy to use; default infers from cases dataset.",
    )
    parser.add_argument(
        "--n",
        type=int,
        default=DEFAULT_B1_SAMPLE,
        help="Sample size for B-1 (ignored for B-0/CSIC). Default 30.",
    )
    parser.add_argument(
        "--labels",
        default=None,
        help="Optional labels-*.jsonl to annotate auto-derived layer/rule_id "
        "alongside each case. Defaults to <input dir>/labels-... if present.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output markdown path. Default: sibling <eval>-sample-<n>.md or "
        "<eval>-manual.md when no sampling.",
    )
    args = parser.parse_args()

    cases_path = Path(args.cases)
    if not cases_path.is_file():
        print(f"not a file: {cases_path}", file=sys.stderr)
        return 2
    cases = _load_jsonl(cases_path)
    if not cases:
        print(f"no cases in {cases_path}", file=sys.stderr)
        return 1

    eval_name = args.eval if args.eval != "auto" else _infer_eval(cases)
    full_size = len(cases)
    selected = select(cases, eval_name, args.n)

    # Auto-locate labels file if not provided
    labels_path = Path(args.labels) if args.labels else None
    if labels_path is None:
        guess = cases_path.with_name(cases_path.name.replace("cases-", "labels-", 1))
        if guess.is_file():
            labels_path = guess
    labels_by_id: dict[str, dict] = {}
    if labels_path and labels_path.is_file():
        for label in _load_jsonl(labels_path):
            labels_by_id[label.get("case_id", "")] = label

    md = build_checklist(selected, labels_by_id, eval_name, full_size=full_size)

    if args.output:
        out = Path(args.output)
    else:
        if eval_name == "b1" and len(selected) < full_size:
            out = cases_path.with_name(f"{eval_name}-sample-{len(selected)}.md")
        else:
            out = cases_path.with_name(f"{eval_name}-manual.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(f"📄 {out}  ({len(selected)} / {full_size} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
