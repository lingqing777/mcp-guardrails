"""Scenario-Playbook: WAF2 evaluator.

Reads scenario-playbook/scenarios.jsonl (30 multi-step attack chains),
sends ALL steps of each scenario to WAF2 (unlike M-Bench-Core which sends
only the last step). WAF2 is stateless, so each step is evaluated independently.

case_id: ``sp:waf2:<NNNN>`` (4-digit padded row index).

Usage:
    PYTHONPATH=. python3 -m waf2.rag.scripts.run_waf2_on_scenario_playbook \\
        --waf2 http://localhost:8081 \\
        --jsonl waf2/rag/eval/scenario-playbook/scenarios.jsonl \\
        --out-dir waf2/rag/eval/runs/<date>-scenario-playbook/
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]

sys.path.insert(0, str(HERE.parent))
from _eval_cases import (  # noqa: E402
    parse_waf2_headers,
    stable_case_id,
    write_cases_jsonl,
)


# ---------- WAF2 client ----------


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
        print(f"⚠️  config update failed: {e}", file=sys.stderr)


def send_one(
    waf2_url: str, method: str, path: str, body: str
) -> tuple[str, str, dict]:
    """Return (outcome, category, headers)."""
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


def build_mcp_envelope(tool: str, args: dict) -> str:
    """Wrap {tool, args} as JSON-RPC tools/call body for POST /mcp."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    }
    return json.dumps(payload, ensure_ascii=False)


# ---------- dataset loader ----------


def load_scenarios(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


# ---------- record building ----------


def build_step_record(
    *,
    case_id: str,
    row_index: int,
    scenario: dict,
    step_num: int,
    step: dict,
    outcome: str,
    detected_category: str,
    telemetry: dict[str, Any],
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "dataset": "scenario-playbook",
        "round": "waf2",
        "row_index": row_index,
        "step_num": step_num,
        "label": "attack",
        "family": scenario.get("family", "call_chain"),
        "subcategory": scenario.get("subcategory", ""),
        "platform": scenario.get("platform", ""),
        "scenario_description": scenario.get("scenario_description", ""),
        "tool": step.get("tool", ""),
        "outcome": outcome,
        "detected_category": detected_category or telemetry.get("detected_category", ""),
        "detected_namespace": f"waf2.{detected_category or telemetry.get('detected_category', '')}",
        "latency_ms": telemetry.get("latency_ms", 0),
        "local_score_total": telemetry.get("local_score_total", 0.0),
        "rag_used": telemetry.get("rag_used", False),
        "rag_top_score": telemetry.get("rag_top_score", 0.0),
        "rag_top_category": telemetry.get("rag_top_category", ""),
        "route": telemetry.get("route", ""),
        "reasons": telemetry.get("reasons") or [],
        "expected_chain": scenario.get("expected_chain", ""),
        "expected_block_step": scenario.get("expected_block_step"),
        "expected_layer": scenario.get("expected_layer", ""),
        "tag": scenario.get("tag", ""),
        "scenario_case_id": scenario.get("case_id", ""),
    }


# ---------- runner ----------


def run_waf2(
    *,
    waf2_url: str,
    scenarios: list[dict],
) -> tuple[list[dict], Counter]:
    """Evaluate all steps of all scenarios. Returns (records, counts)."""
    outcomes: Counter[str] = Counter()
    records: list[dict] = []
    width = max(2, len(str(len(scenarios) - 1)))

    for i, scenario in enumerate(scenarios):
        case_id_base = stable_case_id("sp", "waf2", str(i).zfill(width))
        steps = scenario.get("steps", [])
        for step_num, step in enumerate(steps, 1):
            tool = step.get("tool", "")
            args = step.get("args", {})
            body = build_mcp_envelope(tool, args)
            outcome, cat, resp_headers = send_one(waf2_url, "POST", "/mcp", body)
            outcomes[outcome] += 1
            telemetry = parse_waf2_headers(resp_headers)
            if outcome == "blocked" and not telemetry.get("detected_category"):
                telemetry["detected_category"] = cat or ""

            step_case_id = f"{case_id_base}:s{step_num}"
            rec = build_step_record(
                case_id=step_case_id,
                row_index=i,
                scenario=scenario,
                step_num=step_num,
                step=step,
                outcome=outcome,
                detected_category=cat,
                telemetry=telemetry,
            )
            records.append(rec)

        if (i + 1) % 10 == 0:
            print(
                f"  [waf2-scenario-playbook] {i + 1}/{len(scenarios)} "
                f"blocked={outcomes['blocked']} passed={outcomes['passed']} "
                f"err={outcomes['upstream_error']}",
                file=sys.stderr,
            )

    return records, outcomes


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--waf2", default="http://localhost:8081", help="WAF2 base URL")
    ap.add_argument("--jsonl", required=True, help="path to scenarios.jsonl")
    ap.add_argument("--out-dir", required=True, help="output dir")
    args = ap.parse_args(argv)

    src = Path(args.jsonl)
    if not src.exists():
        print(f"jsonl not found: {src}", file=sys.stderr)
        return 2
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios = load_scenarios(src)
    print(f"[waf2-scenario-playbook] loaded {len(scenarios)} scenarios", file=sys.stderr)

    # Enable eval mode
    _post_config(args.waf2, {"eval_mode": True, "eval_fail_closed": False})

    records, outcomes = run_waf2(waf2_url=args.waf2, scenarios=scenarios)

    out_path = out_dir / "cases-scenario-playbook-waf2.jsonl"
    n = write_cases_jsonl(out_path, records)
    print(
        f"[waf2-scenario-playbook] DONE  outcomes={dict(outcomes)}  → {out_path} ({n} 行)",
        file=sys.stderr,
    )

    # Restore non-eval config
    _post_config(args.waf2, {"eval_mode": False})
    return 0


if __name__ == "__main__":
    sys.exit(main())
