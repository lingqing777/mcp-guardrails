"""Local request normalization for WAF2.

This module is intentionally deterministic and dependency-free. It prepares a
decoded view of the request before rules, RAG, LLM, or ReAct run.
"""

from __future__ import annotations

import ast
import base64
import html
import json
import posixpath
import re
import urllib.parse
from typing import Any, Dict, Iterable, List, Tuple


PERCENT_ENC_RE = re.compile(r"%[0-9a-fA-F]{2}")
UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}")
HTML_ENTITY_RE = re.compile(r"&(?:#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);")
BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")
OVERLONG_SLASH_RE = re.compile(r"%(?:c0%af|e0%80%af|c1%9c)", re.IGNORECASE)
SQL_COMMENT_RE = re.compile(r"(--[^\n\r]*|/\*.*?\*/|#.*?$)", re.DOTALL | re.MULTILINE)
WHITESPACE_RE = re.compile(r"\s+")

SUSPICIOUS_DECODE_TERMS = (
    "select",
    "union",
    "script",
    "javascript:",
    "../",
    "/etc/passwd",
    "whoami",
    "curl ",
    "wget ",
    "ignore previous",
    "system prompt",
    "webhook",
    "token",
    "secret",
)


def _dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _url_decode_layers(text: str, layers: int = 2) -> Tuple[str, List[str]]:
    methods = []
    current = text or ""
    for idx in range(layers):
        if "%" not in current and "+" not in current:
            break
        try:
            decoded = urllib.parse.unquote_plus(current)
        except Exception:
            break
        if decoded == current:
            break
        current = decoded
        methods.append(f"url_decode_{idx + 1}")
    return current, methods


def double_url_decode(text: str) -> str:
    """Apply URL decoding up to two times. Public helper for downstream scorers.

    Stops early when a decode pass yields no change. Always returns a string.
    """
    decoded, _ = _url_decode_layers(text or "", layers=2)
    return decoded


def has_residual_percent(text: str) -> bool:
    """True when the input still contains a `%XX` percent-encoded sequence.

    Use after `double_url_decode` to detect inputs that intentionally bury
    encoded payloads three or more layers deep.
    """
    return bool(PERCENT_ENC_RE.search(text or ""))


def _decode_unicode_escapes(text: str) -> Tuple[str, bool]:
    if not text or not UNICODE_ESCAPE_RE.search(text):
        return text or "", False

    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            if token.startswith("\\u"):
                return chr(int(token[2:], 16))
            return chr(int(token[2:], 16))
        except Exception:
            return token

    decoded = UNICODE_ESCAPE_RE.sub(repl, text)
    return decoded, decoded != text


def _decode_html_entities(text: str) -> Tuple[str, bool]:
    if not text or not HTML_ENTITY_RE.search(text):
        return text or "", False
    decoded = html.unescape(text)
    return decoded, decoded != text


def _normalize_sql_text(text: str) -> Tuple[str, bool]:
    if not text:
        return "", False
    without_comments = SQL_COMMENT_RE.sub(" ", text)
    normalized = WHITESPACE_RE.sub(" ", without_comments).strip()
    return normalized, normalized != text


def _normalize_path(path: str) -> Tuple[str, bool]:
    if not path:
        return "", False
    parsed = urllib.parse.urlsplit(path)
    normalized_path = posixpath.normpath(parsed.path or "/")
    if parsed.path.endswith("/") and not normalized_path.endswith("/"):
        normalized_path += "/"
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    rebuilt = urllib.parse.urlunsplit(("", "", normalized_path, parsed.query, parsed.fragment))
    return rebuilt, rebuilt != path


def _try_parse_json(value: str) -> Any:
    """Parse a string as JSON; on failure fall back to Python literal eval.

    The fallback only accepts standard literals (dict/list/tuple/str/number/
    bool/None) so it cannot execute code. This handles the common case where
    a request body embeds a Python repr of a structure (single-quoted dict),
    e.g. InjecAgent's `tool_response` field.
    """
    if not value:
        return None
    s = value.strip()
    if not s or s[0] not in "{[\"'":
        return None
    try:
        return json.loads(s)
    except Exception:
        pass
    if s[0] not in "{[(":
        return None
    try:
        return ast.literal_eval(s)
    except Exception:
        return None


def _collect_json_strings(value: Any, out: List[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            out.append(str(key))
            _collect_json_strings(item, out, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _collect_json_strings(item, out, depth + 1)
    elif isinstance(value, str):
        out.append(value)
        nested = _try_parse_json(value)
        if nested is not None:
            _collect_json_strings(nested, out, depth + 1)
    elif value is not None:
        out.append(str(value))


def _json_string_fragments(body: str) -> Tuple[List[str], bool]:
    parsed = _try_parse_json(body)
    if parsed is None:
        return [], False
    fragments: List[str] = []
    _collect_json_strings(parsed, fragments)
    return _dedupe(fragments), True


def _decode_base64_candidates(text: str) -> Tuple[List[Dict[str, Any]], bool]:
    decoded_items: List[Dict[str, Any]] = []
    for token in BASE64_CANDIDATE_RE.findall(text or ""):
        if len(token) < 24:
            continue
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
            decoded = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        printable_ratio = sum(1 for c in decoded if c.isprintable() or c in "\n\t\r") / max(len(decoded), 1)
        if printable_ratio < 0.75:
            continue
        lowered = decoded.lower()
        suspicious = any(term in lowered for term in SUSPICIOUS_DECODE_TERMS)
        if suspicious:
            decoded_items.append(
                {
                    "source": token[:80],
                    "decoded": decoded[:500],
                    "printable_ratio": round(printable_ratio, 3),
                    "suspicious": True,
                }
            )
    return decoded_items, bool(decoded_items)


def _decode_text(text: str) -> Tuple[str, List[str], Dict[str, Any]]:
    methods: List[str] = []
    current = text or ""
    meta: Dict[str, Any] = {
        "percent_count": len(PERCENT_ENC_RE.findall(current)),
        "unicode_escape_count": len(UNICODE_ESCAPE_RE.findall(current)),
        "html_entity_count": len(HTML_ENTITY_RE.findall(current)),
        "zero_width_count": len(ZERO_WIDTH_RE.findall(current)),
    }

    if meta["zero_width_count"]:
        current = ZERO_WIDTH_RE.sub("", current)
        methods.append("remove_zero_width")

    if OVERLONG_SLASH_RE.search(current):
        current = OVERLONG_SLASH_RE.sub("/", current)
        methods.append("overlong_utf8_slash_decode")

    current, url_methods = _url_decode_layers(current, layers=2)
    methods.extend(url_methods)

    current, changed = _decode_unicode_escapes(current)
    if changed:
        methods.append("unicode_escape_decode")

    current, changed = _decode_html_entities(current)
    if changed:
        methods.append("html_entity_decode")

    sql_normalized, changed = _normalize_sql_text(current)
    if changed:
        methods.append("sql_comment_whitespace_normalize")
        meta["sql_normalized"] = sql_normalized[:1000]

    meta["changed"] = bool(methods) or current != (text or "")
    return current, methods, meta


def normalize_request(method: str, path: str, body: str) -> Dict[str, Any]:
    """Return original, decoded, extracted, and scoring-friendly request views."""
    original_path = path or ""
    original_body = body or ""

    decoded_path, path_methods, path_meta = _decode_text(original_path)
    decoded_body, body_methods, body_meta = _decode_text(original_body)
    normalized_path, path_norm_changed = _normalize_path(decoded_path)
    if path_norm_changed:
        path_methods.append("path_normalize")

    json_fragments, parsed_json = _json_string_fragments(decoded_body)
    fragment_decoded: List[str] = []
    fragment_methods: List[str] = []
    for fragment in json_fragments:
        decoded_fragment, methods, _ = _decode_text(fragment)
        fragment_decoded.append(decoded_fragment)
        fragment_methods.extend([f"json_fragment_{m}" for m in methods])

    b64_items, has_b64 = _decode_base64_candidates("\n".join([decoded_path, decoded_body, *json_fragments]))
    b64_decoded = [item["decoded"] for item in b64_items]

    methods_used = _dedupe([*path_methods, *body_methods, *fragment_methods])
    if parsed_json:
        methods_used.append("json_parse")
    if has_b64:
        methods_used.append("base64_candidate_decode")

    candidate_texts = _dedupe(
        [
            original_path,
            original_body,
            decoded_path,
            decoded_body,
            normalized_path,
            *json_fragments,
            *fragment_decoded,
            *b64_decoded,
        ]
    )
    analysis_text = "\n".join(candidate_texts)

    return {
        "method": (method or "GET").upper(),
        "original": {
            "path": original_path,
            "body": original_body,
        },
        "decoded": {
            "path": decoded_path,
            "body": decoded_body,
            "normalized_path": normalized_path,
            "json_fragments": json_fragments,
            "json_decoded_fragments": fragment_decoded,
            "base64_decoded": b64_items,
        },
        "analysis_text": analysis_text,
        "methods": methods_used,
        "signals": {
            "changed": bool(methods_used) or original_path != normalized_path or original_body != decoded_body,
            "path": path_meta,
            "body": body_meta,
            "json_parsed": parsed_json,
            "base64_candidates": len(b64_items),
        },
        "summary": {
            "methods": methods_used[:12],
            "changed": bool(methods_used) or original_path != normalized_path or original_body != decoded_body,
            "percent_count": path_meta.get("percent_count", 0) + body_meta.get("percent_count", 0),
            "unicode_escape_count": path_meta.get("unicode_escape_count", 0) + body_meta.get("unicode_escape_count", 0),
            "html_entity_count": path_meta.get("html_entity_count", 0) + body_meta.get("html_entity_count", 0),
            "zero_width_count": path_meta.get("zero_width_count", 0) + body_meta.get("zero_width_count", 0),
            "base64_decoded_count": len(b64_items),
            "json_fragment_count": len(json_fragments),
        },
    }
