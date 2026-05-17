"""Shared helpers for per-case JSONL output across CSIC / B-0 / B-1 eval scripts.

Consumes the `X-Waf2-*` response headers emitted by WAF2 when `eval_mode=true`
(see `waf2/eval_headers.py`) and produces the canonical `cases-*.jsonl` schema
defined in change `add-waf2-eval-failure-analysis-loop`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


AMBIGUOUS_SCORE_THRESHOLD = 0.40
AMBIGUOUS_RAG_THRESHOLD = 0.55

_BODY_TRUNCATE = 2048


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _get_header(headers: Any, name: str) -> str:
    """Case-insensitive header lookup, tolerating dict / list-of-tuples / Mapping."""
    if headers is None:
        return ""
    target = name.lower()
    if hasattr(headers, "items"):
        for k, v in headers.items():
            if str(k).lower() == target:
                return str(v) if v is not None else ""
        return ""
    try:
        for k, v in headers:
            if str(k).lower() == target:
                return str(v) if v is not None else ""
    except TypeError:
        return ""
    return ""


def parse_waf2_headers(headers: Any) -> dict[str, Any]:
    """Parse X-Waf2-* headers into a structured telemetry dict.

    Returns a dict with stable keys even when headers are missing — callers can
    treat the return value as always-present, with zero/empty fallbacks.
    """
    top_str = _get_header(headers, "X-Waf2-Local-Score-Top")
    local_top: dict[str, float] = {}
    if top_str:
        for pair in top_str.split(","):
            if ":" in pair:
                k, v = pair.rsplit(":", 1)
                k = k.strip()
                if k:
                    local_top[k] = _coerce_float(v.strip())

    reasons_str = _get_header(headers, "X-Waf2-Reasons")
    reasons = [r for r in reasons_str.split("|") if r] if reasons_str else []

    norm_str = _get_header(headers, "X-Waf2-Normalize-Meta")
    normalize_meta: dict[str, Any] = {}
    if norm_str:
        for pair in norm_str.split(","):
            if "=" not in pair:
                continue
            k, v = pair.split("=", 1)
            k = k.strip()
            v = v.strip()
            if not k:
                continue
            if k in ("frags", "b64", "pct", "uni"):
                normalize_meta[k] = _coerce_int(v)
            elif k == "changed":
                normalize_meta[k] = v == "1"
            else:
                normalize_meta[k] = v

    return {
        "eval_mode": _get_header(headers, "X-Waf2-Eval-Mode") == "true",
        "outcome_hdr": _get_header(headers, "X-Waf2-Outcome"),
        "detected_category": _get_header(headers, "X-Waf2-Detected-Category"),
        "local_score_total": _coerce_float(_get_header(headers, "X-Waf2-Local-Score-Total")),
        "local_score_top": local_top,
        "rag_used": _get_header(headers, "X-Waf2-Rag-Used") == "true",
        "rag_top_score": _coerce_float(_get_header(headers, "X-Waf2-Rag-Top-Score")),
        "rag_top_category": _get_header(headers, "X-Waf2-Rag-Top-Category"),
        "route": _get_header(headers, "X-Waf2-Route"),
        "reasons": reasons,
        "normalize_meta": normalize_meta,
        "latency_ms": _coerce_int(_get_header(headers, "X-Waf2-Latency-Ms")),
    }


def classify_record_kind(
    expected: str,
    outcome: str,
    telemetry: Mapping[str, Any],
    expected_category: str | None = None,
) -> str | None:
    """Return one of false_negative / false_positive / miscategorized / ambiguous,
    or None to skip.

    Recording rule (design.md D2 + R7 extension):
        - outcome != expected → false_negative or false_positive
        - outcome == blocked AND expected == blocked AND detected_category
          mismatches expected_category → miscategorized (TP with wrong label)
        - outcome == passed AND signals high → ambiguous (close-to-block TN)
        - otherwise → skip (clean TP / TN)
    """
    if outcome not in ("blocked", "passed", "upstream_error"):
        outcome = "upstream_error"

    if outcome != expected:
        if expected == "blocked":
            return "false_negative"
        if expected == "passed":
            return "false_positive"
        return None

    # outcome == expected
    if outcome == "blocked":
        # TP: check miscategorized signal (only when caller supplies a known category)
        detected = str(telemetry.get("detected_category") or "").strip()
        target = (expected_category or "").strip()
        if target and detected and detected != target:
            return "miscategorized"
        return None  # clean TP

    if outcome != "passed":
        return None

    # passed-when-expected-passed: check ambiguous signals
    if _coerce_float(telemetry.get("local_score_total")) >= AMBIGUOUS_SCORE_THRESHOLD:
        return "ambiguous"
    if _coerce_float(telemetry.get("rag_top_score")) >= AMBIGUOUS_RAG_THRESHOLD:
        return "ambiguous"
    return None


def stable_case_id(dataset: str, *parts: Any) -> str:
    """Build a stable, human-readable case_id.

    For CSIC the canonical identifier is body-hash; for B-0/B-1 it is
    `<dataset>:<row>` so the eval scripts can pass `dataset, row_index` and the
    helper composes a unique stable id. Callers may also pass the body to
    request a body-hash cross-check (see `body_hash`).
    """
    parts_str = ":".join(str(p) for p in parts if p is not None and p != "")
    if not parts_str:
        return dataset
    return f"{dataset}:{parts_str}"


def body_hash(body: str) -> str:
    if not body:
        return "0" * 12
    return hashlib.sha1(body.encode("utf-8", errors="ignore")).hexdigest()[:12]


def truncate_body(body: str, limit: int = _BODY_TRUNCATE) -> str:
    if not body:
        return ""
    if len(body) <= limit:
        return body
    return body[: limit - 3] + "..."


def build_case_record(
    *,
    case_id: str,
    dataset: str,
    round_or_split: str,
    expected: str,
    outcome: str,
    record_kind: str,
    method: str,
    path: str,
    body: str,
    telemetry: Mapping[str, Any],
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct one row of the canonical per-case JSONL schema."""
    record = {
        "case_id": case_id,
        "body_hash": body_hash(body),
        "dataset": dataset,
        "round_or_split": round_or_split,
        "expected": expected,
        "outcome": outcome,
        "record_kind": record_kind,
        "method": method,
        "path": path,
        "body": truncate_body(body),
        "detected_category": telemetry.get("detected_category", ""),
        "local_score_total": _coerce_float(telemetry.get("local_score_total")),
        "local_score_top": dict(telemetry.get("local_score_top") or {}),
        "rag_used": bool(telemetry.get("rag_used")),
        "rag_top_score": _coerce_float(telemetry.get("rag_top_score")),
        "rag_top_category": telemetry.get("rag_top_category", ""),
        "route": telemetry.get("route", ""),
        "reasons": list(telemetry.get("reasons") or []),
        "normalize_meta": dict(telemetry.get("normalize_meta") or {}),
        "latency_ms": _coerce_int(telemetry.get("latency_ms")),
    }
    if extra:
        for k, v in extra.items():
            if k not in record:
                record[k] = v
    return record


def write_cases_jsonl(path: Path, records: Iterable[Mapping[str, Any]]) -> int:
    """Write one record per line. Returns count written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n += 1
    return n
