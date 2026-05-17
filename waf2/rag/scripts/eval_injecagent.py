"""Evaluate WAF2 against the InjecAgent indirect-prompt-injection benchmark.

InjecAgent's test cases simulate the canonical IPI scenario:
  1. User asks agent to perform a benign action (e.g. fetch product reviews).
  2. The agent calls a legitimate "user tool".
  3. The tool's response embeds an attacker instruction inside otherwise
     legitimate content (e.g. inside a customer review).
  4. The agent is now expected to call an "attacker tool" to carry out the
     adversary's instruction.

WAF2 sits at the HTTP layer and would see the **Tool Response** body as it
flows from the tool back to the agent. The most informative thing we can
measure is: when WAF2 inspects a response body that *embeds* an attacker
instruction inside otherwise normal content, does it block?

The benchmark has 4 splits:
  - dh_base       510  Direct Harm,    plain attacker instruction
  - dh_enhanced   510  Direct Harm,    reinforced with hacking prompt
  - ds_base       544  Data Stealing,  plain attacker instruction
  - ds_enhanced   544  Data Stealing,  reinforced
                ─────
  total          2108

Default: run all 4 splits with `response` wrap (tool-response body to
/api/process-data). One round only (RAG ON), since RAG OFF/ON has been
shown to produce identical decisions on similar inputs.

Usage:
  PYTHONPATH=. python3 -m waf2.rag.scripts.eval_injecagent \
      --waf2 http://localhost:8081 [--splits dh_base,ds_base] [--limit 100]
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]

sys.path.insert(0, str(HERE.parent))
from _eval_cases import (
    build_case_record,
    classify_record_kind,
    parse_waf2_headers,
    stable_case_id,
    write_cases_jsonl,
)
INJECAGENT_DIR = PROJECT_ROOT / "waf2" / "rag" / "external" / "InjecAgent" / "data"

ALL_SPLITS = ("dh_base", "dh_enhanced", "ds_base", "ds_enhanced")


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


def load_split(split: str) -> list[dict]:
    path = INJECAGENT_DIR / f"test_cases_{split}.json"
    return json.load(open(path, encoding="utf-8"))


def _parse_tool_parameters(raw: str) -> dict:
    """InjecAgent stores parameters as a Python-literal string."""
    if not raw:
        return {}
    try:
        return ast.literal_eval(raw)
    except Exception:
        try:
            return json.loads(raw)
        except Exception:
            return {}


def case_to_response_body(case: dict) -> str:
    """Build an HTTP body that mirrors the tool response the agent would see."""
    return json.dumps(
        {
            "user_tool": case.get("User Tool", ""),
            "user_instruction": case.get("User Instruction", ""),
            "tool_response": case.get("Tool Response", ""),
        },
        ensure_ascii=False,
    )


def send_one(waf2_url: str, body: str) -> tuple[str, str, dict]:
    url = waf2_url.rstrip("/") + "/api/process-data"
    data = body.encode()
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/json"}
    )
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


def run_split(waf2_url: str, split: str, limit: int | None) -> dict:
    cases = load_split(split)
    if limit:
        cases = cases[:limit]
    print(f"\n[InjecAgent] split={split}  N={len(cases)}")

    by_attack_type = defaultdict(Counter)
    outcomes = Counter()
    detected_category = Counter()
    case_records: list[dict] = []

    for i, case in enumerate(cases, start=1):
        body = case_to_response_body(case)
        outcome, cat, resp_headers = send_one(waf2_url, body)
        atk_type = case.get("Attack Type", "unknown")
        by_attack_type[atk_type][outcome] += 1
        outcomes[outcome] += 1
        if outcome == "blocked" and cat:
            detected_category[cat] += 1

        telemetry = parse_waf2_headers(resp_headers)
        if outcome == "blocked" and not telemetry.get("detected_category"):
            telemetry["detected_category"] = cat or ""
        # All InjecAgent cases are indirect prompt injection.
        kind = classify_record_kind(
            "blocked", outcome, telemetry, expected_category="prompt_injection"
        )
        if kind:
            case_records.append(
                build_case_record(
                    case_id=stable_case_id("b1", split, i - 1),
                    dataset="b1",
                    round_or_split=split,
                    expected="blocked",
                    outcome=outcome,
                    record_kind=kind,
                    method="POST",
                    path="/api/process-data",
                    body=body,
                    telemetry=telemetry,
                    extra={
                        "split": split,
                        "attack_type": atk_type,
                        "user_tool": case.get("User Tool", ""),
                        "expected_category": "prompt_injection",
                    },
                )
            )

        if i % 50 == 0:
            br = outcomes["blocked"] / max(i, 1) * 100
            print(f"  [{i:>4}/{len(cases)}] blocked={outcomes['blocked']} passed={outcomes['passed']} err={outcomes['upstream_error']}  BR={br:.1f}%")

    rows = []
    for atk_type, counts in sorted(by_attack_type.items()):
        total = sum(counts.values())
        valid = total - counts["upstream_error"] - counts["other"]
        br = (counts["blocked"] / valid) if valid else 0.0
        rows.append({
            "attack_type": atk_type,
            "total": total,
            "blocked": counts["blocked"],
            "passed": counts["passed"],
            "upstream_error": counts["upstream_error"],
            "other": counts["other"],
            "block_rate": br,
        })

    return {
        "split": split,
        "n": len(cases),
        "outcomes": dict(outcomes),
        "detected_category": dict(detected_category),
        "rows": rows,
        "cases": case_records,
    }


def print_split_summary(result: dict) -> None:
    print(f"\n──── {result['split']} (N={result['n']}) ────")
    print(f"  Outcomes: {result['outcomes']}")
    valid = result["outcomes"].get("blocked", 0) + result["outcomes"].get("passed", 0)
    if valid:
        br = result["outcomes"].get("blocked", 0) / valid * 100
        asr = 100 - br
        print(f"  Block rate: {br:.1f}%   ASR (Attack Success Rate): {asr:.1f}%")
    print(f"  Detected categories: {result['detected_category']}")
    print(f"\n  {'attack_type':30s} {'tot':>4s} {'blk':>4s} {'pas':>4s} {'err':>4s} {'BR':>7s}")
    print("  " + "-" * 60)
    for r in result["rows"]:
        print(f"  {r['attack_type']:30s} {r['total']:>4d} {r['blocked']:>4d} {r['passed']:>4d} {r['upstream_error']:>4d} {r['block_rate']*100:>6.1f}%")


def main() -> None:
    parser = argparse.ArgumentParser(description="InjecAgent eval against WAF2")
    parser.add_argument("--waf2", default="http://localhost:8081")
    parser.add_argument("--splits", default=",".join(ALL_SPLITS), help="comma-sep list of splits")
    parser.add_argument("--limit", type=int, default=None, help="per-split case limit")
    parser.add_argument(
        "--rag",
        choices=["on", "off"],
        default="on",
        help="RAG state during evaluation (default on)",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="JSON report output path",
    )
    parser.add_argument(
        "--cases-out-dir",
        default=None,
        help="Directory to write per-case JSONL (cases-b1-<split>.jsonl). "
        "Default: same directory as --report.",
    )
    args = parser.parse_args()

    _post_config(
        args.waf2,
        {"rag_enabled": args.rag == "on", "eval_mode": True, "eval_fail_closed": False},
    )

    splits = [s.strip() for s in args.splits.split(",") if s.strip()]
    results = {}
    for split in splits:
        results[split] = run_split(args.waf2, split, args.limit)
        print_split_summary(results[split])

    _post_config(args.waf2, {"eval_mode": False})

    # Aggregate
    total_outcomes = Counter()
    for r in results.values():
        for k, v in r["outcomes"].items():
            total_outcomes[k] += v
    print("\n========================================================")
    print(f"  Aggregate across {len(splits)} splits:")
    print(f"    {dict(total_outcomes)}")
    valid = total_outcomes["blocked"] + total_outcomes["passed"]
    if valid:
        br = total_outcomes["blocked"] / valid * 100
        print(f"    Block rate: {br:.1f}%   ASR: {100 - br:.1f}%")

    if args.report:
        report_path = Path(args.report)
    else:
        report_path = PROJECT_ROOT / "waf2" / "rag" / "eval" / "injecagent-eval-report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {k: {kk: vv for kk, vv in v.items() if kk != "cases"} for k, v in results.items()}
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n📄 Report: {report_path}")

    # Per-case JSONL output (add-waf2-eval-failure-analysis-loop)
    cases_dir = Path(args.cases_out_dir) if args.cases_out_dir else report_path.parent
    total_cases = 0
    for split, r in results.items():
        cases = r.get("cases") or []
        if not cases:
            continue
        slug = split.replace("_", "-")
        filename = f"cases-b1-{slug}.jsonl"
        n = write_cases_jsonl(cases_dir / filename, cases)
        total_cases += n
        print(f"📄 per-case 已写入: {cases_dir / filename} ({n} 条)")
    if total_cases == 0:
        print("⚠️ 未写入任何 cases — 检查 WAF2 是否启用 eval_mode 且 X-Waf2-* header 透出")


if __name__ == "__main__":
    main()
