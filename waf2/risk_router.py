"""Risk routing for WAF2 local-first pipeline."""

from __future__ import annotations

from typing import Any, Dict


ROUTE_STATIC_BLOCK = "static_block"
ROUTE_FAST_PASS = "fast_pass"
ROUTE_KNOWLEDGE_EVIDENCE = "knowledge_evidence"
ROUTE_LOCAL_LLM = "local_llm_one_shot"
ROUTE_REACT = "react_deep_inspection"
ROUTE_FALLBACK = "fallback"

BUSINESS_PATH_TERMS = (
    "/api/login",
    "/api/users",
    "/api/products",
    "/api/order",
    "/api/orders",
    "/api/comment",
    "/api/comments",
    "/api/post",
    "/api/ticket",
    "/api/db_query",
    "/api/forum",
    "/api/settings",
    "/products/",
    "/profile/",
    "/search",
    "/tienda1/publico/entrar.jsp",
    "/tienda1/publico/registro.jsp",
    "/tienda1/publico/anadir.jsp",
    "/tienda1/publico/pagar.jsp",
    "/tienda1/publico/vaciar.jsp",
    "/tienda1/publico/caracteristicas.jsp",
    "/tienda1/miembros/editar.jsp",
)

BUSINESS_BODY_TERMS = (
    "username",
    "password",
    "password_hash",
    "email",
    "items",
    "text",
    "title",
    "body",
    "query",
    "sku",
    "post_id",
    "theme",
    "locale",
    "precio",
    "cantidad",
    "carrito",
)


def _business_context(path: str, normalized: Dict[str, Any]) -> bool:
    lowered_path = (path or "").lower()
    if not any(term in lowered_path for term in BUSINESS_PATH_TERMS):
        return False
    blob = str(normalized.get("analysis_text", "")).lower()
    return any(term in blob for term in BUSINESS_BODY_TERMS) or lowered_path.startswith(("/products/", "/profile/", "/search"))


def decide_route(
    method: str,
    path: str,
    normalized: Dict[str, Any],
    score: Dict[str, Any],
    rag_used: bool,
    top_score: float,
    config: Any,
) -> Dict[str, Any]:
    """Choose the next analysis route after local scoring and RAG retrieval."""
    summary = normalized.get("summary", {})
    signals = normalized.get("signals", {})
    methods = set(summary.get("methods", []))
    score_value = float(score.get("top_score", 0.0) or 0.0)
    category = score.get("top_category", "none")

    reasons = []
    if score_value:
        reasons.append(f"local_score={category}:{score_value:.3f}")
    if summary.get("percent_count", 0):
        reasons.append(f"percent_enc={summary.get('percent_count')}")
    if summary.get("unicode_escape_count", 0):
        reasons.append("unicode_escape")
    if summary.get("html_entity_count", 0):
        reasons.append("html_entity")
    if summary.get("base64_decoded_count", 0):
        reasons.append("base64_decoded")
    if summary.get("json_fragment_count", 0):
        reasons.append("json_fragments")
    if rag_used:
        reasons.append(f"rag_score={top_score:.3f}")

    block_threshold = float(getattr(config, "local_score_block_threshold", 0.88))
    gray_threshold = float(getattr(config, "local_score_gray_threshold", 0.35))
    fast_threshold = float(getattr(config, "local_score_fast_pass_threshold", 0.12))
    direct_block_enabled = bool(getattr(config, "local_score_direct_block_enabled", True))
    fast_pass_enabled = bool(getattr(config, "local_fast_pass_enabled", True))
    react_rag_threshold = float(getattr(config, "react_rag_score_threshold", 0.68))

    if direct_block_enabled and score_value >= block_threshold:
        return {
            "route": ROUTE_STATIC_BLOCK,
            "legacy_route": "static_block",
            "reason": "local attack score exceeded direct-block threshold",
            "reasons": reasons,
            "category": category,
            "score": score_value,
        }

    complex_decode = bool(
        summary.get("base64_decoded_count", 0)
        or "unicode_escape_decode" in methods
        or "json_fragment_unicode_escape_decode" in methods
        or summary.get("zero_width_count", 0)
    )
    encoded_gray = bool(summary.get("percent_count", 0) >= 4 or complex_decode)
    high_rag = bool(rag_used and top_score >= react_rag_threshold)
    mcp_or_prompt = category in {"prompt_injection", "data_exfiltration", "sensitive_data_exposure"}
    business_context = _business_context(path, normalized)

    if bool(getattr(config, "react_routing_enabled", True)) and not (business_context and score_value < gray_threshold) and (
        encoded_gray
        or high_rag
        or (mcp_or_prompt and score_value >= gray_threshold)
    ):
        return {
            "route": ROUTE_REACT,
            "legacy_route": "react",
            "reason": "gray-zone request requires deep inspection",
            "reasons": reasons,
            "category": category,
            "score": score_value,
        }

    if rag_used or score_value >= gray_threshold:
        return {
            "route": ROUTE_LOCAL_LLM,
            "legacy_route": "one_shot",
            "reason": "gray-zone request requires local LLM judgment",
            "reasons": reasons,
            "category": category,
            "score": score_value,
        }

    method_upper = (method or "GET").upper()
    changed = bool(summary.get("changed") or signals.get("changed"))
    if fast_pass_enabled and business_context and score_value < gray_threshold:
        return {
            "route": ROUTE_FAST_PASS,
            "legacy_route": "fast_pass",
            "reason": "low-risk known business context",
            "reasons": [*reasons, "business_context"],
            "category": category,
            "score": score_value,
        }

    if fast_pass_enabled and score_value <= fast_threshold and not changed and method_upper in {"GET", "HEAD", "OPTIONS"}:
        return {
            "route": ROUTE_FAST_PASS,
            "legacy_route": "fast_pass",
            "reason": "low-risk request below fast-pass threshold",
            "reasons": reasons,
            "category": category,
            "score": score_value,
        }

    return {
        "route": ROUTE_LOCAL_LLM,
        "legacy_route": "one_shot",
        "reason": "default local LLM judgment",
        "reasons": reasons,
        "category": category,
        "score": score_value,
    }
