"""Extract detectable false-negative samples from CSIC failures into a regression JSONL.

This is a one-time helper used by the harden-waf2-local-scorer-probe-and-decode
change. It reads waf2/rag/eval/failures.jsonl, decodes each entry, and keeps
only those whose decoded path or body contains a strong attack signal that the
new scorer rules (legacy probes, double-decoded SQLi, header injection) should
catch.

Output: waf2/rag/eval/probe-fn-regression.jsonl
"""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]
SRC = PROJECT_ROOT / "waf2" / "rag" / "eval" / "failures.jsonl"
DST = PROJECT_ROOT / "waf2" / "rag" / "eval" / "probe-fn-regression.jsonl"


PROBE_PATH_PATTERNS = re.compile(
    r"(?:\.(?:inc|htr|asa|cmd|bak|old|swp)(?:[/?#]|$))"
    r"|/_vti_(?:pvt|bin|cnf)"
    r"|/iisadmpwd/"
    r"|/scripts/"
    r"|/msadc/",
    re.I,
)

SQLI_PATTERNS = re.compile(
    r"'\s*(?:or|and)\s*'?[a-z\d]+'?\s*=\s*'?[a-z\d]+"
    r"|\"\s*(?:or|and)\s*\"?\d+\"?\s*=\s*\"?\d+"
    r"|union\s+(?:all\s+)?select"
    r"|/etc/passwd",
    re.I,
)


def categorize(entry: dict) -> str | None:
    path = entry.get("path", "") or ""
    body = entry.get("body", "") or ""
    raw = f"{path}?{body}"
    decoded_once = urllib.parse.unquote_plus(raw)
    decoded_twice = urllib.parse.unquote_plus(decoded_once)

    if PROBE_PATH_PATTERNS.search(path) or PROBE_PATH_PATTERNS.search(decoded_once):
        return "legacy_web_probe"
    if SQLI_PATTERNS.search(decoded_once) or SQLI_PATTERNS.search(decoded_twice):
        return "sql_injection"
    return None


def main() -> int:
    if not SRC.exists():
        print(f"Source not found: {SRC}")
        return 1

    out = []
    seen: set[tuple[str, str, str]] = set()
    with SRC.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("kind") != "false_negative":
                continue
            if entry.get("round") != "RAG ON":
                continue
            category = categorize(entry)
            if not category:
                continue
            key = (entry.get("method", ""), entry.get("path", ""), entry.get("body", ""))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "method": entry["method"],
                "path": entry["path"],
                "body": entry.get("body", ""),
                "expected_category": category,
                "source": "csic-failures-2026-05-10",
            })

    DST.parent.mkdir(parents=True, exist_ok=True)
    with DST.open("w", encoding="utf-8") as f:
        for row in out:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    by_cat: dict[str, int] = {}
    for row in out:
        by_cat[row["expected_category"]] = by_cat.get(row["expected_category"], 0) + 1
    print(f"Wrote {len(out)} samples to {DST}")
    for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {count:3d}  {cat}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
