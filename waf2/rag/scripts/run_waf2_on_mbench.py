"""M-Bench-Core: WAF2 evaluator.

Reads waf2/rag/eval/m-bench-core/{attacks,benign}.jsonl, dispatches each
record to single-step or multi-step evaluation based on ``family``:

  - char_injection / prompt_injection_and_priv_esc (single-step) → send a
    synthetic POST /mcp request whose body wraps {tool, args} as a
    JSON-RPC ``tools/call`` payload.
  - call_chain (multi-step) → WAF2 is stateless, so we evaluate ONLY the
    last step (``steps[-1]``); the output record carries
    ``waf2_evaluated_step=len(steps)`` and the report disclosure surfaces
    that ``call_chain`` measurement is "last-step only" by architecture.

For benign records, label/source/paired_with are passed through to the
output record so the merge script can compute hard-neg vs template FP
breakdown.

case_id: ``mbc:rag-on:<NNNN>`` / ``mbc:rag-off:<NNNN>`` (4-digit padded
row index).

Usage:
    PYTHONPATH=. python3 -m waf2.rag.scripts.run_waf2_on_mbench \\
        --waf2 http://localhost:8081 \\
        --jsonl waf2/rag/eval/m-bench-core/attacks.jsonl \\
        --rag-mode both \\
        --out-dir waf2/rag/eval/runs/<date>-mbench-pilot/

See openspec/changes/add-mbench-core-attack-benchmark/design.md (D3) and
openspec/specs/m-bench-core-evaluation/spec.md (Req §5).
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
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

# ---------- WAF2 client helpers (adapted from eval_prompt_injection.py) ----------


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
    """Return (outcome, category, headers).

    outcome ∈ {"blocked", "passed", "upstream_error", "other"}
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


# ---------- dataset loader ----------


def load_mbench(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


# ---------- envelope construction ----------


def build_mcp_envelope(tool: str, args: dict) -> str:
    """Wrap {tool, args} as a JSON-RPC tools/call body suitable for POST /mcp."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args or {}},
    }
    return json.dumps(payload, ensure_ascii=False)


def envelope_for_record(rec: dict) -> tuple[str, str, int | None]:
    """Return (path, body, waf2_evaluated_step).

    waf2_evaluated_step is None for single-step records, len(steps) for
    multi-step records (because WAF2 is stateless and only the last step
    is sent).
    """
    family = rec.get("family", "")
    if family == "call_chain":
        steps = rec.get("steps") or []
        if not steps:
            raise ValueError(f"call_chain record {rec.get('case_id')} has empty steps")
        last = steps[-1]
        body = build_mcp_envelope(last.get("tool", ""), last.get("args") or {})
        return "/mcp", body, len(steps)
    # single-step (attack or benign)
    body = build_mcp_envelope(rec.get("tool", ""), rec.get("args") or {})
    return "/mcp", body, None


# ---------- detected_namespace mapping ----------


def waf2_detected_namespace(category: str) -> str:
    if not category:
        return ""
    return f"waf2.{category}"


# ---------- record building ----------


def build_record(
    *,
    case_id: str,
    round_slug: str,
    row_index: int,
    record: dict,
    outcome: str,
    detected_category: str,
    telemetry: dict[str, Any],
    waf2_evaluated_step: int | None,
) -> dict[str, Any]:
    is_multi = record.get("family") == "call_chain"
    out = {
        "case_id": case_id,
        "dataset": "mbench",
        "round": round_slug,
        "row_index": row_index,
        "label": record.get("label", ""),
        "family": record.get("family", ""),
        "subcategory": record.get("subcategory", ""),
        "tool": "" if is_multi else record.get("tool", ""),
        "outcome": outcome,
        "detected_category": detected_category or telemetry.get("detected_category", ""),
        "detected_namespace": waf2_detected_namespace(
            detected_category or telemetry.get("detected_category", "")
        ),
        "reason": "",
        "latency_ms": telemetry.get("latency_ms", 0),
        "local_score_total": telemetry.get("local_score_total", 0.0),
        "rag_used": telemetry.get("rag_used", False),
        "rag_top_score": telemetry.get("rag_top_score", 0.0),
        "rag_top_category": telemetry.get("rag_top_category", ""),
        "route": telemetry.get("route", ""),
        "reasons": telemetry.get("reasons") or [],
        "expected_block_by": record.get("expected_block_by"),
        "expected_chain": record.get("expected_chain"),
        "expected_block_step": record.get("expected_block_step"),
        "blocked_at_step": None,  # WAF2 is single-step view
        "waf2_evaluated_step": waf2_evaluated_step,
        "paired_with": record.get("paired_with"),
        "source": record.get("source"),
        "tag": record.get("tag", ""),
        "is_multi_step": is_multi,
    }
    return out


# ---------- runner ----------


def run_round(
    *,
    waf2_url: str,
    rows: list[dict],
    round_slug: str,
) -> tuple[list[dict], Counter]:
    """Run all rows under one config (RAG ON or OFF). Returns (records, counts)."""
    outcomes: Counter[str] = Counter()
    records: list[dict] = []
    width = max(4, len(str(len(rows) - 1)))
    for i, row in enumerate(rows):
        path, body, eval_step = envelope_for_record(row)
        outcome, cat, resp_headers = send_one(waf2_url, "POST", path, body)
        outcomes[outcome] += 1
        telemetry = parse_waf2_headers(resp_headers)
        if outcome == "blocked" and not telemetry.get("detected_category"):
            telemetry["detected_category"] = cat or ""
        case_id = stable_case_id("mbench", round_slug, str(i).zfill(width))
        rec = build_record(
            case_id=case_id,
            round_slug=round_slug,
            row_index=i,
            record=row,
            outcome=outcome,
            detected_category=cat,
            telemetry=telemetry,
            waf2_evaluated_step=eval_step,
        )
        records.append(rec)
        if (i + 1) % 50 == 0:
            print(
                f"  [{round_slug}] {i + 1}/{len(rows)} blocked={outcomes['blocked']} "
                f"passed={outcomes['passed']} err={outcomes['upstream_error']}",
                file=sys.stderr,
            )
    return records, outcomes


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--waf2", default="http://localhost:8081", help="WAF2 base URL")
    ap.add_argument(
        "--jsonl", required=True, help="path to attacks.jsonl or benign.jsonl"
    )
    ap.add_argument(
        "--rag-mode",
        choices=["on", "off", "both"],
        default="both",
    )
    ap.add_argument("--out-dir", required=True, help="output dir for cases JSONL")
    args = ap.parse_args(argv)

    src = Path(args.jsonl)
    if not src.exists():
        print(f"jsonl not found: {src}", file=sys.stderr)
        return 2
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_mbench(src)
    print(f"[waf2-mbench] loaded {len(rows)} rows from {src}", file=sys.stderr)
    base_name = src.stem  # 'attacks' or 'benign'

    rounds = []
    if args.rag_mode in ("off", "both"):
        rounds.append(("rag-off", {"rag_enabled": False, "eval_mode": True, "eval_fail_closed": False}))
    if args.rag_mode in ("on", "both"):
        rounds.append(("rag-on", {"rag_enabled": True, "eval_mode": True, "eval_fail_closed": False}))

    for round_slug, cfg in rounds:
        _post_config(args.waf2, cfg)
        records, outcomes = run_round(
            waf2_url=args.waf2, rows=rows, round_slug=round_slug
        )
        out_path = out_dir / f"cases-mbench-{base_name}-{round_slug}.jsonl"
        n = write_cases_jsonl(out_path, records)
        print(
            f"[waf2-mbench] {round_slug} DONE  outcomes={dict(outcomes)}  → {out_path} ({n} 行)",
            file=sys.stderr,
        )

    # Restore non-eval config
    _post_config(args.waf2, {"eval_mode": False})
    return 0


if __name__ == "__main__":
    sys.exit(main())
