"""Evaluate WAF2 against the probe false-negative regression set.

Reads waf2/rag/eval/probe-fn-regression.jsonl and sends each request to a
running WAF2 reverse-proxy. Reports how many were blocked.

A success means the local scorer (legacy probe, double-decode, header rules)
recognizes the attack without needing the LLM path.

Usage:
  python -m waf2.rag.scripts.eval_probe_regression --waf2 http://localhost:8081
"""
from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]
DEFAULT_DATASET = PROJECT_ROOT / "waf2" / "rag" / "eval" / "probe-fn-regression.jsonl"


def send_one(waf2_url: str, method: str, path: str, body: str) -> tuple[bool, str]:
    waf2_url = waf2_url.rstrip("/")
    url = f"{waf2_url}{path}"
    if body:
        data = body.encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        data, headers = None, {}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
            return False, ""
    except urllib.error.HTTPError as he:
        if he.code != 403:
            return False, f"http_{he.code}"
        try:
            err = json.loads(he.read().decode("utf-8", errors="ignore"))
            return True, err.get("category", "") or ""
        except Exception:
            return True, ""
    except Exception as exc:
        return False, f"net_error:{type(exc).__name__}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--waf2", default="http://localhost:8081")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    rows = []
    with open(args.dataset, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    blocked = 0
    misses: list[dict] = []
    cat_counter: Counter[str] = Counter()
    for i, row in enumerate(rows, 1):
        ok, cat = send_one(args.waf2, row["method"], row["path"], row.get("body", ""))
        if ok:
            blocked += 1
            cat_counter[cat or "<empty>"] += 1
            if args.verbose:
                print(f"  [{i:3d}] BLOCK  cat={cat:<22s} {row['method']:5s} {row['path'][:80]}")
        else:
            misses.append(row)
            print(f"  [{i:3d}] MISS   ({cat or 'pass'}) {row['method']:5s} {row['path'][:80]}")

    total = len(rows)
    rate = blocked / total * 100 if total else 0.0
    print(f"\nProbe-FN regression: {blocked}/{total} blocked ({rate:.1f}%)")
    print("Detected categories:")
    for cat, count in cat_counter.most_common():
        print(f"  {count:3d}  {cat}")
    if misses:
        print(f"\nStill missed: {len(misses)} (target: ≤ {max(0, total - int(total * 0.9))})")

    # Acceptance: ≥ 90% blocked
    return 0 if rate >= 90.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
