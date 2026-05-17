"""Build X-Waf2-* diagnostic response headers when eval_mode=true.

These headers let evaluation scripts capture per-case decision signals
(scores, RAG, route, reasons, normalize meta, latency) without parsing
WAF2 stderr logs. Production responses are unaffected — the calling
code must only invoke this helper when config.eval_mode is true.
"""

from __future__ import annotations

from typing import Any, Dict


_HEADER_VALUE_MAX_BYTES = 256


def _truncate_header(value: str, limit: int = _HEADER_VALUE_MAX_BYTES) -> str:
    # HTTP headers are transported as latin-1; non-encodable code points
    # (e.g. CJK in route reasons) MUST be replaced before length check.
    safe = value.encode("latin-1", errors="replace").decode("latin-1")
    encoded = safe.encode("utf-8", errors="ignore")
    if len(encoded) <= limit:
        return safe
    truncated = encoded[: max(limit - 3, 0)].decode("utf-8", errors="ignore")
    return truncated + "..."


def _format_score_top(summary: Any) -> str:
    if not isinstance(summary, list):
        return ""
    pairs = []
    for item in summary[:3]:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category", "") or "").strip()
        try:
            score = float(item.get("score", 0.0) or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        if not category:
            continue
        pairs.append(f"{category}:{score:.2f}")
    return ",".join(pairs)


def _format_reasons(reasons: Any) -> str:
    if isinstance(reasons, list):
        return "|".join(str(r) for r in reasons if r is not None)
    if reasons is None:
        return ""
    return str(reasons)


def _format_normalize_meta(norm: Any) -> str:
    if not isinstance(norm, dict):
        return ""
    parts = [
        f"frags={int(norm.get('json_fragment_count', 0) or 0)}",
        f"b64={int(norm.get('base64_decoded_count', 0) or 0)}",
        f"pct={int(norm.get('percent_count', 0) or 0)}",
        f"uni={int(norm.get('unicode_escape_count', 0) or 0)}",
        f"changed={'1' if norm.get('changed') else '0'}",
    ]
    return ",".join(parts)


def build_eval_headers(result: Dict[str, Any], latency_ms: float) -> Dict[str, str]:
    """Build X-Waf2-* headers from a request-analysis result dict.

    Caller is responsible for gating on config.eval_mode. Missing fields
    in `result` are tolerated — they emit empty / zero values.
    """
    if not isinstance(result, dict):
        result = {}

    blocked = bool(result.get("blocked"))
    outcome = "blocked" if blocked else "passed"
    detected_category = str(result.get("category") or "") if blocked else ""

    try:
        local_total = float(result.get("local_attack_top_score", 0.0) or 0.0)
    except (TypeError, ValueError):
        local_total = 0.0
    local_top = _format_score_top(result.get("local_attack_score"))

    rag_used = bool(result.get("rag_augmented"))
    try:
        rag_top_score = float(result.get("rag_top_score", 0.0) or 0.0)
    except (TypeError, ValueError):
        rag_top_score = 0.0
    rag_cats = result.get("rag_evidence_categories") or []
    rag_top_cat = ""
    if isinstance(rag_cats, list) and rag_cats:
        rag_top_cat = str(rag_cats[0] or "")

    route = str(result.get("route") or "")
    reasons_str = _format_reasons(result.get("route_reasons"))
    norm_str = _format_normalize_meta(result.get("normalization"))

    try:
        latency_int = int(latency_ms)
    except (TypeError, ValueError):
        latency_int = 0

    headers = {
        "X-Waf2-Eval-Mode": "true",
        "X-Waf2-Outcome": outcome,
        "X-Waf2-Detected-Category": _truncate_header(detected_category),
        "X-Waf2-Local-Score-Total": f"{local_total:.3f}",
        "X-Waf2-Local-Score-Top": _truncate_header(local_top),
        "X-Waf2-Rag-Used": "true" if rag_used else "false",
        "X-Waf2-Rag-Top-Score": f"{rag_top_score:.3f}",
        "X-Waf2-Rag-Top-Category": _truncate_header(rag_top_cat),
        "X-Waf2-Route": _truncate_header(route),
        "X-Waf2-Reasons": _truncate_header(reasons_str),
        "X-Waf2-Normalize-Meta": _truncate_header(norm_str),
        "X-Waf2-Latency-Ms": str(latency_int),
    }
    return headers
