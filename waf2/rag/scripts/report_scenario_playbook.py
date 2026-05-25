"""Scenario-Playbook: merge WAF1+WAF2 results and render thesis table 5.2.

Input: cases-scenario-playbook-waf1-full.jsonl + cases-scenario-playbook-waf2.jsonl
Output: scenario-playbook-summary.md with per-platform detection rates.

Usage:
    PYTHONPATH=. python3 -m waf2.rag.scripts.report_scenario_playbook \\
        --waf1-cases <run-dir>/cases-scenario-playbook-waf1-full.jsonl \\
        --waf2-cases <run-dir>/cases-scenario-playbook-waf2.jsonl \\
        --out <run-dir>/scenario-playbook-summary.md
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


PLATFORM_LABELS = {
    "wordpress": "WordPress",
    "woocommerce": "WooCommerce",
    "supabase": "Supabase",
}


def load_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def group_waf2_by_scenario(waf2_records: list[dict]) -> dict[str, list[dict]]:
    """Group WAF2 per-step records by scenario_case_id."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for rec in waf2_records:
        sid = rec.get("scenario_case_id", "")
        if sid:
            grouped[sid].append(rec)
    return grouped


def merge_scenario(
    waf1_rec: dict,
    waf2_steps: list[dict],
) -> dict[str, Any]:
    """Merge WAF1 chain result + WAF2 per-step results into scenario verdict."""
    scenario_case_id = waf1_rec.get("scenario_case_id", "")
    platform = waf1_rec.get("platform", "")

    # WAF1 result
    waf1_blocked = waf1_rec.get("outcome") == "blocked"
    waf1_blocked_at = waf1_rec.get("blocked_at_step")

    # WAF2 result: blocked if any step blocked
    waf2_blocked = any(s.get("outcome") == "blocked" for s in waf2_steps)
    waf2_blocked_at = None
    for s in sorted(waf2_steps, key=lambda x: x.get("step_num", 0)):
        if s.get("outcome") == "blocked":
            waf2_blocked_at = s.get("step_num")
            break

    # Overall
    overall_blocked = waf1_blocked or waf2_blocked
    if waf1_blocked and waf2_blocked:
        actual_layer = "both"
    elif waf1_blocked:
        actual_layer = "waf1"
    elif waf2_blocked:
        actual_layer = "waf2"
    else:
        actual_layer = "none"

    # First blocking step
    block_steps = []
    if waf1_blocked_at:
        block_steps.append(("waf1", waf1_blocked_at))
    if waf2_blocked_at:
        block_steps.append(("waf2", waf2_blocked_at))
    block_steps.sort(key=lambda x: x[1])
    actual_block_step = block_steps[0][1] if block_steps else None

    # Gray zone check
    needs_gray_zone = any(
        s.get("route", "") in ("react_deep_inspection", "fallback")
        for s in waf2_steps
    )

    return {
        "case_id": scenario_case_id,
        "platform": platform,
        "scenario_description": waf1_rec.get("scenario_description", ""),
        "subcategory": waf1_rec.get("subcategory", ""),
        "tag": waf1_rec.get("tag", ""),
        "num_steps": len(waf1_rec.get("step_verdicts", [])),
        "expected_block_step": waf1_rec.get("expected_block_step"),
        "expected_layer": waf1_rec.get("expected_layer", ""),
        "overall_blocked": overall_blocked,
        "actual_layer": actual_layer,
        "actual_block_step": actual_block_step,
        "needs_gray_zone": needs_gray_zone,
        "waf1_outcome": waf1_rec.get("outcome", ""),
        "waf1_blocked_at_step": waf1_blocked_at,
        "waf2_blocked": waf2_blocked,
        "waf2_blocked_at_step": waf2_blocked_at,
    }


def generate_summary(results: list[dict]) -> str:
    """Generate Markdown summary matching thesis table 5.2."""
    by_platform: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_platform[r["platform"]].append(r)

    lines = [
        "# Scenario-Playbook Evaluation Report",
        "",
        f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total scenarios**: {len(results)}",
        "",
        "## Table 5.2 — Scenario-Playbook Detection Results",
        "",
        "| 场景类别 | 案例数 | 成功拦截数 | 控制面拦截 | 数据面拦截 | 需灰区分析 | 检测率(%) |",
        "|----------|--------|-----------|-----------|-----------|-----------|----------|",
    ]

    total_n = 0
    total_blocked = 0
    total_waf1 = 0
    total_waf2 = 0
    total_gray = 0

    for platform in ["wordpress", "woocommerce", "supabase"]:
        recs = by_platform.get(platform, [])
        n = len(recs)
        blocked = sum(1 for r in recs if r["overall_blocked"])
        waf1_count = sum(1 for r in recs if r["actual_layer"] in ("waf1", "both"))
        waf2_count = sum(1 for r in recs if r["actual_layer"] in ("waf2", "both"))
        gray = sum(1 for r in recs if r["needs_gray_zone"])
        rate = (blocked / n * 100) if n else 0

        total_n += n
        total_blocked += blocked
        total_waf1 += waf1_count
        total_waf2 += waf2_count
        total_gray += gray

        lines.append(
            f"| {PLATFORM_LABELS[platform]} | {n} | {blocked} | "
            f"{waf1_count} | {waf2_count} | {gray} | {rate:.1f} |"
        )

    total_rate = (total_blocked / total_n * 100) if total_n else 0
    lines.append(
        f"| **综合** | **{total_n}** | **{total_blocked}** | "
        f"**{total_waf1}** | **{total_waf2}** | **{total_gray}** | "
        f"**{total_rate:.1f}** |"
    )

    lines.extend([
        "",
        "## Per-Scenario Detail",
        "",
        "| case_id | platform | blocked | layer | block_step | gray_zone | tag |",
        "|---------|----------|---------|-------|------------|-----------|-----|",
    ])

    for r in results:
        blocked_str = "Yes" if r["overall_blocked"] else "No"
        gray_str = "Yes" if r["needs_gray_zone"] else ""
        lines.append(
            f"| `{r['case_id']}` | {r['platform']} | {blocked_str} | "
            f"{r['actual_layer']} | {r['actual_block_step'] or '-'} | "
            f"{gray_str} | {r['tag']} |"
        )

    return "\n".join(lines)


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--waf1-cases", required=True, help="WAF1 results JSONL")
    ap.add_argument("--waf2-cases", required=True, help="WAF2 results JSONL")
    ap.add_argument("--out", required=True, help="output markdown path")
    args = ap.parse_args(argv)

    waf1_path = Path(args.waf1_cases)
    waf2_path = Path(args.waf2_cases)
    if not waf1_path.exists():
        print(f"WAF1 cases not found: {waf1_path}", file=sys.stderr)
        return 2
    if not waf2_path.exists():
        print(f"WAF2 cases not found: {waf2_path}", file=sys.stderr)
        return 2

    waf1_records = load_jsonl(waf1_path)
    waf2_records = load_jsonl(waf2_path)
    waf2_grouped = group_waf2_by_scenario(waf2_records)

    print(f"[report-scenario-playbook] WAF1: {len(waf1_records)} records", file=sys.stderr)
    print(f"[report-scenario-playbook] WAF2: {len(waf2_records)} step records", file=sys.stderr)

    results = []
    for waf1_rec in waf1_records:
        sid = waf1_rec.get("scenario_case_id", "")
        waf2_steps = waf2_grouped.get(sid, [])
        merged = merge_scenario(waf1_rec, waf2_steps)
        results.append(merged)

    report = generate_summary(results)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"[report-scenario-playbook] wrote {out_path} ({len(results)} scenarios)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
