"""Evaluate WAF2 against the internal prompt-injection seed corpus.

Reads waf2/rag/eval/prompt-injection-eval.jsonl (produced by
build_prompt_injection_eval.py), sends each request to a running WAF2
reverse-proxy, and reports per-(subcategory, wrap) block rates plus a
combined route distribution.

A "block" means WAF2 returned HTTP 403 (or any non-2xx that originates from
WAF2 rather than the upstream — upstream errors are counted separately so they
don't inflate the block rate).

Usage:
  PYTHONPATH=. python3 -m waf2.rag.scripts.eval_prompt_injection \
      --waf2 http://localhost:8081 [--rag-on|--rag-off]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]
DEFAULT_DATASET = PROJECT_ROOT / "waf2" / "rag" / "eval" / "prompt-injection-eval.jsonl"

sys.path.insert(0, str(HERE.parent))
from _eval_cases import (
    build_case_record,
    classify_record_kind,
    parse_waf2_headers,
    stable_case_id,
    write_cases_jsonl,
)


def _post_config(waf2_url: str, payload: dict) -> None:
    url = waf2_url.rstrip("/") + "/waf2/config"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        print(f"⚠️  config update failed: {e}")


def send_one(waf2_url: str, method: str, path: str, body: str) -> tuple[str, str, dict]:
    """Return (outcome, category, headers).

    outcome ∈ {"blocked", "passed", "upstream_error", "other"}
    category is parsed from the JSON error body when blocked, else "".
    headers is a dict of the WAF2 response headers (incl. X-Waf2-*).
    """
    url = waf2_url.rstrip("/") + path
    data = body.encode() if body else None
    headers = {"Content-Type": "application/json"} if body else {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=200) as resp:
            resp.read()
            return "passed", "", dict(resp.headers.items())
    except urllib.error.HTTPError as he:
        resp_headers = dict(he.headers.items()) if he.headers else {}
        if he.code == 403:
            try:
                body_text = he.read().decode("utf-8", errors="replace")
                parsed = json.loads(body_text)
                if parsed.get("error") and "WAF2" in str(parsed.get("error", "")):
                    return "blocked", parsed.get("category", ""), resp_headers
            except Exception:
                pass
            return "upstream_error", "", resp_headers
        if 500 <= he.code < 600:
            return "upstream_error", "", resp_headers
        return "other", "", resp_headers
    except urllib.error.URLError:
        return "upstream_error", "", {}
    except Exception:
        return "other", "", {}


def load_dataset(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def run_round(waf2_url: str, dataset: list[dict], label: str) -> dict:
    print(f"\n[eval] 🚀 Round: prompt-injection {label}  (N={len(dataset)})")
    # (subcat, wrap) -> Counter of outcomes
    matrix = defaultdict(Counter)
    detected_category_counter = Counter()
    outcomes = Counter()
    cases: list[dict] = []
    round_slug = "rag-on" if label.upper().endswith("ON") else "rag-off"

    for i, sample in enumerate(dataset, start=1):
        outcome, cat, resp_headers = send_one(
            waf2_url, sample["method"], sample["path"], sample["body"]
        )
        key = (sample["subcategory"], sample["wrap"])
        matrix[key][outcome] += 1
        outcomes[outcome] += 1
        if outcome == "blocked" and cat:
            detected_category_counter[cat] += 1

        telemetry = parse_waf2_headers(resp_headers)
        if outcome == "blocked" and not telemetry.get("detected_category"):
            telemetry["detected_category"] = cat or ""
        # All B-0 subcategories are prompt-injection variants.
        kind = classify_record_kind(
            "blocked", outcome, telemetry, expected_category="prompt_injection"
        )
        if kind:
            cases.append(
                build_case_record(
                    case_id=stable_case_id("b0", round_slug, i - 1),
                    dataset="b0",
                    round_or_split=round_slug,
                    expected="blocked",
                    outcome=outcome,
                    record_kind=kind,
                    method=sample["method"],
                    path=sample["path"],
                    body=sample["body"],
                    telemetry=telemetry,
                    extra={
                        "subcategory": sample.get("subcategory", ""),
                        "wrap": sample.get("wrap", ""),
                        "expected_category": "prompt_injection",
                    },
                )
            )

        if i % 20 == 0:
            print(f"  [{i:>3}/{len(dataset)}] blocked={outcomes['blocked']}  passed={outcomes['passed']}  upstream_err={outcomes['upstream_error']}")

    # Per-cell aggregates
    rows = []
    for (subcat, wrap), counts in sorted(matrix.items()):
        total = sum(counts.values())
        valid = total - counts["upstream_error"] - counts["other"]
        block_rate = (counts["blocked"] / valid) if valid else 0.0
        rows.append({
            "subcategory": subcat,
            "wrap": wrap,
            "total": total,
            "blocked": counts["blocked"],
            "passed": counts["passed"],
            "upstream_error": counts["upstream_error"],
            "other": counts["other"],
            "block_rate": block_rate,
        })

    return {
        "label": label,
        "rows": rows,
        "outcomes": dict(outcomes),
        "detected_category": dict(detected_category_counter),
        "cases": cases,
    }


def print_matrix(rows: list[dict]) -> None:
    print(f"\n{'subcategory':35s} {'wrap':10s} {'tot':>4s} {'blk':>4s} {'pas':>4s} {'err':>4s} {'BR':>7s}")
    print("-" * 75)
    for r in rows:
        print(
            f"{r['subcategory']:35s} {r['wrap']:10s} "
            f"{r['total']:>4d} {r['blocked']:>4d} {r['passed']:>4d} "
            f"{r['upstream_error']:>4d} {r['block_rate']*100:>6.1f}%"
        )


def print_summary_by_subcategory(rows: list[dict]) -> None:
    sub_totals = defaultdict(lambda: {"blocked": 0, "passed": 0, "upstream_error": 0, "total": 0})
    for r in rows:
        s = sub_totals[r["subcategory"]]
        s["blocked"] += r["blocked"]
        s["passed"] += r["passed"]
        s["upstream_error"] += r["upstream_error"]
        s["total"] += r["total"]
    print(f"\n{'subcategory':35s} {'tot':>4s} {'blk':>4s} {'pas':>4s} {'err':>4s} {'BR':>7s}")
    print("-" * 64)
    for sub in sorted(sub_totals.keys()):
        s = sub_totals[sub]
        valid = s["total"] - s["upstream_error"]
        br = (s["blocked"] / valid) if valid else 0.0
        print(
            f"{sub:35s} {s['total']:>4d} {s['blocked']:>4d} {s['passed']:>4d} "
            f"{s['upstream_error']:>4d} {br*100:>6.1f}%"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--waf2", default="http://localhost:8081")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--mode", choices=["off", "on", "both"], default="both")
    parser.add_argument(
        "--report",
        default=None,
        help="Optional path to write JSON report (default: alongside dataset)",
    )
    parser.add_argument(
        "--cases-out-dir",
        default=None,
        help="Directory to write per-case JSONL (cases-b0-<round>.jsonl). "
        "Default: same directory as --report.",
    )
    args = parser.parse_args()

    dataset = load_dataset(Path(args.dataset))
    print(f"Loaded {len(dataset)} cases from {args.dataset}")

    results = {}
    if args.mode in ("off", "both"):
        _post_config(args.waf2, {"rag_enabled": False, "eval_mode": True, "eval_fail_closed": False})
        results["off"] = run_round(args.waf2, dataset, "RAG OFF")
    if args.mode in ("on", "both"):
        _post_config(args.waf2, {"rag_enabled": True, "eval_mode": True, "eval_fail_closed": False})
        results["on"] = run_round(args.waf2, dataset, "RAG ON")

    # Restore config after run
    _post_config(args.waf2, {"eval_mode": False})

    # Pretty print
    for label, r in results.items():
        print(f"\n====================================================")
        print(f"  {label.upper()}  outcomes: {r['outcomes']}")
        print(f"  detected categories: {r['detected_category']}")
        print(f"====================================================")
        print_matrix(r["rows"])
        print_summary_by_subcategory(r["rows"])

    # Write JSON report
    if args.report:
        report_path = Path(args.report)
    else:
        report_path = Path(args.dataset).with_name("prompt-injection-eval-report.json")
    # Strip cases from the aggregate report (kept separate as JSONL)
    summary = {k: {kk: vv for kk, vv in v.items() if kk != "cases"} for k, v in results.items()}
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n📄 JSON report: {report_path}")

    # Per-case JSONL output (add-waf2-eval-failure-analysis-loop)
    cases_dir = Path(args.cases_out_dir) if args.cases_out_dir else report_path.parent
    total_cases = 0
    for label, r in results.items():
        cases = r.get("cases") or []
        if not cases:
            continue
        round_slug = "rag-on" if label == "on" else "rag-off"
        filename = f"cases-b0-{round_slug}.jsonl"
        n = write_cases_jsonl(cases_dir / filename, cases)
        total_cases += n
        print(f"📄 per-case 已写入: {cases_dir / filename} ({n} 条)")
    if total_cases == 0:
        print("⚠️ 未写入任何 cases — 检查 WAF2 是否启用 eval_mode 且 X-Waf2-* header 透出")


if __name__ == "__main__":
    main()
