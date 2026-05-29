"""Generate thesis Chapter 5 tables (5.1–5.5, 5.7) from an ablation run directory.

Usage:
    python3 waf2/rag/scripts/report_thesis_tables.py \\
        --run-dir waf2/rag/eval/runs/<date>-ablation-7way-<model>/ \\
        [--out thesis_tables.md]

Reads:
  - index.tsv                     → Table 5.3, 5.4 (per-ablation F1 columns)
  - 3-full/cases-mbench-merged.jsonl → Table 5.1 (per-family), 5.5 (per-chain)
  - 3-full/cases-mbench-*-rag-on.jsonl → Table 5.7 (route distribution)
  - */scenario-playbook-summary.md → Table 5.2, 5.4 (场景化检测率 column)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# ── Constants ──────────────────────────────────────────────────────────────

FAMILY_ZH = {
    "char_injection": "传统字符注入",
    "prompt_injection_and_priv_esc": "提示注入与越权",
    "call_chain": "调用链组合攻击",
}

CHAIN_SUBCATEGORY_ZH = {
    "data_exfiltration": "data_exfiltration",
    "credential_theft": "credential_theft",
    "recon_then_exploit": "recon_then_exploit",
    "supabase_lethal_trifecta": "supabase_lethal_trifecta",
    "prompt_injection_to_exfil": "prompt_injection_to_exfil",
}

ABLATION_DIRS = [
    ("1-waf1-only", "WAF1-only"),
    ("2-waf2-only", "WAF2-only"),
    ("3-full", "Full"),
    ("4-full-no-chain", "Full no-chain"),
    ("5-full-no-dynsql", "Full no-dynSQL"),
    ("6-full-no-rag", "Full no-RAG"),
    ("7-full-no-react", "Full no-ReAct"),
]

ROUTE_ORDER = [
    "static_block",
    "fast_pass",
    "knowledge_evidence",
    "local_llm_one_shot",
    "react_deep_inspection",
    "react_fallback_rag_rescue",
    "fallback",
]

ROUTE_ZH = {
    "static_block": "direct block",
    "fast_pass": "fast pass",
    "knowledge_evidence": "knowledge evidence",
    "local_llm_one_shot": "local_llm_one_shot",
    "react_deep_inspection": "react_deep_inspection",
    "react_fallback_rag_rescue": "react_fallback_rag_rescue",
    "fallback": "fallback",
}


# ── Helpers ────────────────────────────────────────────────────────────────


def load_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def safe_div(num: float, den: float) -> float:
    return num / den if den > 0 else 0.0


def pct(v: float) -> str:
    return f"{v * 100:.1f}"


def active_layers(rec: dict) -> list[str]:
    skipped = set(rec.get("skipped_layers") or [])
    active = []
    if "waf1" not in skipped:
        active.extend(["waf1_strict", "waf1_full"])
    if "waf2" not in skipped:
        active.append("rag_on")
    return active


def case_latency(rec: dict) -> float:
    return sum((rec.get(l) or {}).get("latency_ms") or 0 for l in active_layers(rec))


def parse_scenario_rate(md_path: Path) -> float | None:
    """Extract the 综合 detection rate (%) from a scenario-playbook-summary.md."""
    if not md_path.exists():
        return None
    text = md_path.read_text(encoding="utf-8")
    # Match the 综合 row: | **综合** | **30** | **28** | ... | **93.3** |
    m = re.search(r"\|\s*\*?\*?综合\*?\*?\s*\|.*?\|\s*\*?\*?(\d+\.?\d*)\*?\*?\s*\|", text)
    if m:
        return float(m.group(1))
    return None


def parse_scenario_detail(md_path: Path) -> dict[str, dict]:
    """Parse per-platform stats from scenario-playbook-summary.md."""
    if not md_path.exists():
        return {}
    text = md_path.read_text(encoding="utf-8")
    result = {}
    # Match platform rows: | WordPress | 10 | 9 | 5 | 4 | 2 | 90.0 |
    for m in re.finditer(
        r"\|\s*(WordPress|WooCommerce|Supabase)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+\.?\d*)\s*\|",
        text,
    ):
        result[m.group(1)] = {
            "cases": int(m.group(2)),
            "blocked": int(m.group(3)),
            "waf1": int(m.group(4)),
            "waf2": int(m.group(5)),
            "gray": int(m.group(6)),
            "rate": float(m.group(7)),
        }
    return result


# ── Table 5.1: Per-family metrics (Full config) ──────────────────────────


def compute_table_51(records: list[dict]) -> str:
    attacks = [r for r in records if r.get("label") == "attack"]
    benigns = [r for r in records if r.get("label") == "benign"]
    FP_global = sum(1 for r in benigns if r.get("dual_blocked"))
    n_benigns = len(benigns)

    by_family: dict[str, list[dict]] = defaultdict(list)
    for r in attacks:
        by_family[r.get("family", "?")].append(r)

    rows = []
    for fam in ("char_injection", "prompt_injection_and_priv_esc", "call_chain"):
        rows.append(_family_row(FAMILY_ZH.get(fam, fam), by_family.get(fam, []), FP_global, n_benigns))
    rows.append(_family_row("综合", attacks, FP_global, n_benigns))

    lines = [
        "## 表 5.1 M-Bench-Core 核心攻击检测结果",
        "",
        "| 攻击类别 | TP | FN | TN | FP | Precision (%) | Recall (%) | F1 (%) | FPR (%) | AvgTime (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, m in rows:
        lines.append(
            f"| {label} | {m['TP']} | {m['FN']} | {m['TN']} | {m['FP']} | "
            f"{pct(m['P'])} | {pct(m['R'])} | {pct(m['F1'])} | {pct(m['FPR'])} | {m['avgT']:.0f} |"
        )
    return "\n".join(lines)


def _family_row(label: str, group: list[dict], FP: int, n_benigns: int) -> tuple[str, dict]:
    TP = sum(1 for r in group if r.get("dual_blocked"))
    FN = len(group) - TP
    TN = n_benigns - FP
    P = safe_div(TP, TP + FP)
    R = safe_div(TP, TP + FN)
    F1 = safe_div(2 * P * R, P + R)
    FPR = safe_div(FP, n_benigns)
    avgT = safe_div(sum(case_latency(r) for r in group), len(group))
    return label, dict(TP=TP, FN=FN, TN=TN, FP=FP, P=P, R=R, F1=F1, FPR=FPR, avgT=avgT)


# ── Table 5.2: Scenario-Playbook (Full config) ──────────────────────────


def compute_table_52(full_dir: Path) -> str:
    md_path = full_dir / "scenario-playbook-summary.md"
    if not md_path.exists():
        return "## 表 5.2 Scenario-Playbook 场景化检测结果\n\n> 数据不可用（scenario-playbook-summary.md 不存在）"

    detail = parse_scenario_detail(md_path)
    lines = [
        "## 表 5.2 Scenario-Playbook 场景化检测结果",
        "",
        "| 场景类别 | 案例数 | 成功拦截数 | 控制面拦截 | 数据面拦截 | 需灰区分析 | 检测率 (%) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    total = {"cases": 0, "blocked": 0, "waf1": 0, "waf2": 0, "gray": 0}
    for platform in ["WordPress", "WooCommerce", "Supabase"]:
        d = detail.get(platform, {"cases": 0, "blocked": 0, "waf1": 0, "waf2": 0, "gray": 0, "rate": 0.0})
        lines.append(
            f"| {platform} | {d['cases']} | {d['blocked']} | "
            f"{d['waf1']} | {d['waf2']} | {d['gray']} | {d['rate']:.1f} |"
        )
        for k in total:
            total[k] += d[k]

    total_rate = safe_div(total["blocked"], total["cases"]) * 100
    lines.append(
        f"| **综合** | **{total['cases']}** | **{total['blocked']}** | "
        f"**{total['waf1']}** | **{total['waf2']}** | **{total['gray']}** | **{total_rate:.1f}** |"
    )
    return "\n".join(lines)


# ── Table 5.3: Baseline comparison (partial — only ablation rows) ───────


def compute_table_53(index_rows: list[tuple[str, list[str]]]) -> str:
    lines = [
        "## 表 5.3 代表性基线对比结果",
        "",
        "| 方案 | Precision (%) | Recall (%) | F1 (%) |",
        "| --- | ---: | ---: | ---: |",
    ]
    label_map = {"WAF1-only": "WAF1-Only", "WAF2-only": "WAF2-Only", "Full": "MCP Guardrails（Full）"}
    for label, cols in index_rows:
        if label in label_map:
            # index.tsv: label, char_F1, pi_F1, chain_F1, recall, F1, avg_atk, avg_ben
            recall = float(cols[3])
            f1 = float(cols[4])
            # Precision derived from F1 and recall: F1 = 2PR/(P+R) → P = F1*R / (2R - F1)
            if 2 * recall - f1 > 0:
                prec = f1 * recall / (2 * recall - f1)
            else:
                prec = 0.0
            lines.append(f"| {label_map[label]} | {pct(prec)} | {pct(recall)} | {pct(f1)} |")
    return "\n".join(lines)


# ── Table 5.4: Ablation results ──────────────────────────────────────────


def compute_table_54(
    index_rows: list[tuple[str, list[str]]],
    scenario_rates: dict[str, float],
) -> str:
    lines = [
        "## 表 5.4 双层架构与关键模块消融结果",
        "",
        "| 配置 | 字符注入 F1 | 提示注入 F1 | 调用链攻击 F1 | 场景化检测率 | 综合 F1 | AvgTime (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, cols in index_rows:
        char_f1 = pct(float(cols[0]))
        pi_f1 = pct(float(cols[1]))
        chain_f1 = pct(float(cols[2]))
        overall_f1 = pct(float(cols[4]))
        avg_time = float(cols[5])
        sp_rate = scenario_rates.get(label, None)
        sp_str = f"{sp_rate:.1f}" if sp_rate is not None else "—"
        lines.append(
            f"| {label} | {char_f1} | {pi_f1} | {chain_f1} | {sp_str} | {overall_f1} | {avg_time:.0f} |"
        )
    return "\n".join(lines)


# ── Table 5.5: Chain subcategory detection ───────────────────────────────


def compute_table_55(records: list[dict]) -> str:
    attacks = [r for r in records if r.get("label") == "attack" and r.get("family") == "call_chain"]

    by_sub: dict[str, list[dict]] = defaultdict(list)
    for r in attacks:
        by_sub[r.get("subcategory", "?")].append(r)

    lines = [
        "## 表 5.5 调用链模式专项检测结果",
        "",
        "| 调用链模式 | 样本数 | 检出数 | 检测率 (%) |",
        "| --- | ---: | ---: | ---: |",
    ]

    total_n = 0
    total_detected = 0
    for sub in ("data_exfiltration", "credential_theft", "recon_then_exploit", "supabase_lethal_trifecta", "prompt_injection_to_exfil"):
        group = by_sub.get(sub, [])
        n = len(group)
        detected = sum(1 for r in group if r.get("dual_blocked"))
        rate = safe_div(detected, n) * 100
        label = CHAIN_SUBCATEGORY_ZH.get(sub, sub)
        lines.append(f"| {label} | {n} | {detected} | {rate:.1f} |")
        total_n += n
        total_detected += detected

    total_rate = safe_div(total_detected, total_n) * 100
    lines.append(f"| **综合** | **{total_n}** | **{total_detected}** | **{total_rate:.1f}** |")
    return "\n".join(lines)


# ── Table 5.7: Route distribution ────────────────────────────────────────


def compute_table_57(run_dir: Path) -> str:
    full_dir = run_dir / "3-full"

    # Load attack and benign rag-on records
    atk_path = full_dir / "cases-mbench-attacks-rag-on.jsonl"
    ben_path = full_dir / "cases-mbench-benign-rag-on.jsonl"

    atk_records = load_jsonl(atk_path) if atk_path.exists() else []
    ben_records = load_jsonl(ben_path) if ben_path.exists() else []

    atk_routes = Counter(r.get("route", "") for r in atk_records)
    ben_routes = Counter(r.get("route", "") for r in ben_records)

    atk_total = len(atk_records)
    ben_total = len(ben_records)

    lines = [
        "## 表 5.7 本地优先路由过程指标",
        "",
        "| 指标 | 攻击样本 | 正常样本 |",
        "| --- | ---: | ---: |",
    ]

    for route in ROUTE_ORDER:
        a = atk_routes.get(route, 0)
        b = ben_routes.get(route, 0)
        a_pct = safe_div(a, atk_total) * 100
        b_pct = safe_div(b, ben_total) * 100
        label = ROUTE_ZH.get(route, route)
        lines.append(f"| {label} | {a} ({a_pct:.1f}%) | {b} ({b_pct:.1f}%) |")

    # Latency stats from merged JSONL
    merged_path = full_dir / "cases-mbench-merged.jsonl"
    if merged_path.exists():
        merged = load_jsonl(merged_path)
        atk_latencies = [case_latency(r) for r in merged if r.get("label") == "attack"]
        ben_latencies = [case_latency(r) for r in merged if r.get("label") == "benign"]
        if atk_latencies:
            atk_latencies.sort()
            avg_atk = sum(atk_latencies) / len(atk_latencies)
            p95_atk = atk_latencies[int(len(atk_latencies) * 0.95)]
            lines.append(f"| Avg Latency (ms) | {avg_atk:.0f} | — |")
            lines.append(f"| P95 Latency (ms) | {p95_atk:.0f} | — |")

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────


def load_index_tsv(path: Path) -> list[tuple[str, list[str]]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 6:
            rows.append((parts[0], parts[1:]))
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-dir", required=True, help="ablation run directory")
    ap.add_argument("--out", default="thesis_tables.md", help="output file")
    args = ap.parse_args(argv)

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"run directory not found: {run_dir}", file=sys.stderr)
        return 2

    index_path = run_dir / "index.tsv"
    if not index_path.exists():
        print(f"index.tsv not found: {index_path}", file=sys.stderr)
        return 2

    index_rows = load_index_tsv(index_path)

    # ── Table 5.1 ──
    full_merged = run_dir / "3-full" / "cases-mbench-merged.jsonl"
    if full_merged.exists():
        records = load_jsonl(full_merged)
        table_51 = compute_table_51(records)
    else:
        table_51 = "## 表 5.1 M-Bench-Core 核心攻击检测结果\n\n> 数据不可用（3-full/cases-mbench-merged.jsonl 不存在）"

    # ── Table 5.2 ──
    table_52 = compute_table_52(run_dir / "3-full")

    # ── Table 5.3 ──
    table_53 = compute_table_53(index_rows)

    # ── Table 5.4 ──
    scenario_rates: dict[str, float] = {}
    for dirname, label in ABLATION_DIRS:
        rate = parse_scenario_rate(run_dir / dirname / "scenario-playbook-summary.md")
        if rate is not None:
            scenario_rates[label] = rate
    table_54 = compute_table_54(index_rows, scenario_rates)

    # ── Table 5.5 ──
    if full_merged.exists():
        table_55 = compute_table_55(records)
    else:
        table_55 = "## 表 5.5 调用链模式专项检测结果\n\n> 数据不可用"

    # ── Table 5.7 ──
    table_57 = compute_table_57(run_dir)

    # ── Assemble ──
    md = "\n\n".join([
        f"# 论文第五章结果表 — {run_dir.name}",
        "",
        table_51,
        table_52,
        table_53,
        table_54,
        table_55,
        table_57,
    ])

    out_path = Path(args.out)
    out_path.write_text(md, encoding="utf-8")
    print(f"[report-thesis-tables] wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
