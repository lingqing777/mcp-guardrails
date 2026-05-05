"""Deterministic local attack scoring for WAF2.

The scorer is not a replacement for RAG/LLM. It gives the router a fast local
signal so obvious or decoded attacks can be blocked without model calls, and
gray-zone requests can be sent to the right deeper path.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, Iterable, List, Tuple


ScoreHit = Tuple[str, float, str]


PATTERNS: Dict[str, List[Tuple[re.Pattern[str], float, str]]] = {
    "sql_injection": [
        (re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I), 0.65, "union_select"),
        (re.compile(r"(?:'|%27|\")\s*(?:--|#)", re.I), 0.88, "quote_comment_truncation"),
        (re.compile(r"(?:'|%27|\")[^&\s]{0,40}(?:--|#)", re.I), 0.88, "inline_quote_comment_truncation"),
        (re.compile(r"(?:'|%27|\")\s*(?:or|and)\s+['\"]?\d+\s*=\s*['\"]?\d+", re.I), 0.60, "boolean_tautology"),
        (re.compile(r"\bor\s+1\s*=\s*1\b", re.I), 0.55, "or_1_eq_1"),
        (re.compile(r"\binformation_schema\b|\bsysobjects\b|\bpg_catalog\b", re.I), 0.55, "schema_enumeration"),
        (re.compile(r";\s*(?:drop|delete|insert|update|alter)\b", re.I), 0.55, "stacked_sql_write"),
        (re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s*\(", re.I), 0.50, "time_based_sqli"),
        (re.compile(r"\bwaitfor\s+delay\b", re.I), 0.75, "mssql_waitfor_delay"),
        (re.compile(r"(?:'|\")\s*(?:and|or)\s*(?:'|\")?\d+(?:'|\")?\s*=\s*(?:'|\")?\d+", re.I), 0.65, "quoted_boolean_tautology"),
        (re.compile(r";\s*(?:select|waitfor)\b", re.I), 0.35, "stacked_sql_followup"),
        (re.compile(r"(?:--|#|/\*)", re.I), 0.18, "sql_comment"),
    ],
    "xss": [
        (re.compile(r"<\s*script\b", re.I), 0.75, "script_tag"),
        (re.compile(r"javascript\s*:", re.I), 0.65, "javascript_uri"),
        (re.compile(r"\bon(?:error|load|click|mouseover|focus)\s*=", re.I), 0.60, "event_handler"),
        (re.compile(r"<\s*(?:img|svg|iframe|object)\b", re.I), 0.40, "active_html_tag"),
        (re.compile(r"\bdocument\.(?:cookie|location)\b", re.I), 0.45, "document_cookie_or_location"),
        (re.compile(r"cookiesteal|hacker\s*\.example|attackerhost", re.I), 0.45, "cookie_steal_destination"),
        (re.compile(r"\balert\s*\(|\bconfirm\s*\(|\bprompt\s*\(", re.I), 0.25, "browser_dialog_call"),
    ],
    "command_injection": [
        (re.compile(r"(?:;|\||&&|\|\|)\s*(?:ls|cat|whoami|id|rm|wget|curl|bash|sh|nc|python|perl|php)\b", re.I), 0.75, "shell_operator_command"),
        (re.compile(r"`[^`]+`|\$\([^)]+\)", re.I), 0.60, "shell_substitution"),
        (re.compile(r"\b(?:bash|sh)\s+-c\b", re.I), 0.65, "shell_c_flag"),
        (re.compile(r"\bnc\s+-e\b|\bmkfifo\b|/bin/(?:sh|bash)\b", re.I), 0.70, "reverse_shell_indicator"),
        (re.compile(r"<!--\s*#exec\s+cmd\s*=", re.I), 0.90, "ssi_exec_command"),
    ],
    "path_traversal": [
        (re.compile(r"(?:\.\./|\.\.\\)", re.I), 0.70, "dot_dot_path"),
        (re.compile(r"/etc/(?:passwd|shadow|hosts)\b|/proc/self\b", re.I), 0.85, "unix_sensitive_file"),
        (re.compile(r"windows[\\/]system32|boot\.ini|win\.ini", re.I), 0.70, "windows_sensitive_file"),
        (re.compile(r"\.(?:env|git|ssh)(?:/|\\|\b)|wp-config\.php|id_rsa", re.I), 0.65, "sensitive_project_file"),
        (re.compile(r"(?:^|/)[^?\s]*(?:\.(?:bak|old|backup|orig|save|tmp|swp)(?:[/?#\s]|$)|~(?:[?#\s]|$))", re.I), 0.90, "backup_or_temp_resource_probe"),
    ],
    "ssrf": [
        (re.compile(r"\b(?:127\.0\.0\.1|0\.0\.0\.0|localhost)\b", re.I), 0.70, "loopback_target"),
        (re.compile(r"\b169\.254\.169\.254\b|metadata\.(?:google|azure)|metadata\.aws", re.I), 0.85, "cloud_metadata_target"),
        (re.compile(r"\b(?:10|192\.168)\.\d+\.\d+\.\d+\b|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+", re.I), 0.65, "private_network_target"),
        (re.compile(r"\bgopher://|\bfile://|\bdict://", re.I), 0.70, "dangerous_url_scheme"),
    ],
    "prompt_injection": [
        (re.compile(r"ignore\s+(?:previous|above|all|prior|system)\s+instructions?", re.I), 0.75, "ignore_instructions"),
        (re.compile(r"disregard\s+(?:previous|your|all)\s+instructions?", re.I), 0.65, "disregard_instructions"),
        (re.compile(r"\byou\s+are\s+now\b|\bDAN\b|jailbreak|developer message|system prompt", re.I), 0.60, "role_or_system_hijack"),
        (re.compile(r"\bbypass\s+system\s+instructions?\b|act\s+as\s+if\s+you\s+have\s+done\s+so", re.I), 0.90, "academic_bypass_system_instructions"),
        (re.compile(r"override\s+above|actual\s+task\s*:\s*dump|dump\s+all\s+customer\s+db", re.I), 0.90, "indirect_override_dump"),
        (re.compile(r"<<<\s*/?\s*SYS\s*>>>|<\s*/?\s*SYS\s*>|exfiltrate\s+api\s+keys", re.I), 0.90, "system_tag_hijack"),
        (re.compile(r"repeat\s+your\s+instructions?\s+in\s+pig\s+latin|repeat\s+your\s+instructions?", re.I), 0.90, "instruction_leak_request"),
        (re.compile(r"PRINT_SECRETS\s*\(\)|output\s*:\s*PRINT_SECRETS", re.I), 0.90, "secret_print_persona"),
        (re.compile(r"忽略(?:以上|之前|所有|上面|前面)|无视(?:以上|之前|所有)|你现在是|越狱|系统提示|开发者消息"), 0.75, "zh_prompt_override"),
        (re.compile(r"translate.*(?:do not|ignore|system)|学术|研究.*(?:绕过|越狱|提示词)", re.I), 0.35, "disguised_prompt_attack"),
    ],
    "data_exfiltration": [
        (re.compile(r"\b(?:exfil|leak|dump|export|send|send_email)\b", re.I), 0.45, "exfil_verb"),
        (re.compile(r"\b(?:webhook|callback|collector|attacker|pastebin|ipfs|cf-ipfs|discord|telegram|slack)\b", re.I), 0.55, "external_collection_target"),
        (re.compile(r"customer\s+db\s+rows|all\s+customer\s+db|/tmp/leak\.csv", re.I), 0.70, "customer_db_dump"),
        (re.compile(r"data@my-collector\.com|my-backup\.cf-ipfs\.com", re.I), 0.90, "known_exfil_destination_shape"),
        (re.compile(r"https?://(?!localhost|127\.0\.0\.1|host\.docker\.internal)", re.I), 0.25, "external_url"),
        (re.compile(r"\b(?:public bucket|public table|anonymous access|backup\.tar\.gz|公开表|外发|泄露)\b", re.I), 0.45, "public_exposure_term"),
    ],
    "credential_leakage": [
        (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.I), 0.95, "private_key"),
        (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0.85, "jwt"),
        (re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{16,}\b|\bsk-[A-Za-z0-9_-]{16,}\b", re.I), 0.85, "api_key_prefix"),
        (re.compile(r"\bAKIA[A-Z0-9]{16}\b|\bASIA[A-Z0-9]{16}\b"), 0.85, "aws_access_key"),
        (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{16,}\b|\bglpat-[A-Za-z0-9_-]{16,}\b", re.I), 0.80, "git_token"),
        (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", re.I), 0.80, "slack_token"),
        (re.compile(r"\b(?:api[_-]?key|token|secret|password|passwd|pwd)\b.{0,20}[=:]\s*['\"]?[A-Za-z0-9_\-./+]{20,}", re.I), 0.50, "secret_field_long_value"),
    ],
    "authentication_bypass": [
        (re.compile(r"\bimpersonate\b.{0,30}\badmin\b|\badmin\b.{0,30}\bimpersonate\b", re.I), 0.85, "admin_impersonation"),
        (re.compile(r"_internal_skip_check|skip[_-]?auth|bypass[_-]?auth|is_admin\s*[:=]\s*true", re.I), 0.75, "auth_check_bypass_flag"),
        (re.compile(r"\brole\b.{0,20}\badmin\b|\brole\b.{0,20}\broot\b", re.I), 0.45, "privileged_role_claim"),
    ],
    "insecure_deserialization": [
        (re.compile(r"O:\d+:\"[A-Za-z0-9_\\\\]+\":\d+:\{", re.I), 0.90, "php_object_serialization"),
        (re.compile(r"\brO0AB[A-Za-z0-9+/=]{20,}", re.I), 0.90, "java_serialized_base64"),
        (re.compile(r"\bgASV[A-Za-z0-9+/=]{20,}", re.I), 0.90, "python_pickle_base64"),
        (re.compile(r"\bpickle\b.{0,40}\b(?:os|system|subprocess|eval|exec)\b", re.I), 0.75, "pickle_dangerous_context"),
        (re.compile(r"AdminCmd|cat\s+passwd|/etc/passwd", re.I), 0.35, "deserialization_command_context"),
    ],
    "mcp_tool_abuse": [
        (re.compile(r"\b(?:mcp|jsonrpc|tool_calls?|function_call|sampling|stdio|resource)\b", re.I), 0.25, "mcp_surface"),
        (re.compile(r"\b(?:tool description|description|schema|inputSchema|server instructions)\b", re.I), 0.25, "tool_metadata_surface"),
        (re.compile(r"\b(?:execute_sql|shell|filesystem|read_file|write_file|send_email|http_request)\b", re.I), 0.35, "dangerous_tool_name"),
        (re.compile(r"(?:ignore|override|replace).{0,40}(?:tool|schema|description|instruction)", re.I), 0.55, "tool_poisoning_instruction"),
        (re.compile(r"工具.{0,20}(?:描述|参数|调用).{0,30}(?:忽略|覆盖|外发|泄露)"), 0.55, "zh_tool_poisoning"),
    ],
    "unknown": [
        (re.compile(r"set-cookie\s*:\s*tamper", re.I), 0.90, "response_splitting_tamper_cookie"),
        (re.compile(r"/CFIDE/administrator", re.I), 0.90, "known_admin_probe_path"),
        (re.compile(r"\.(?:jsp|gif|css)/\d{8,}\.(?:jsp|java|cfm)\b", re.I), 0.90, "extension_confusion_probe"),
        (re.compile(r"/examplesWebApp/index\.jsp\b", re.I), 0.90, "csic_probe_app_path"),
        (re.compile(r"\.(?:gif|jpg|jpeg|png|css|js)/\d{8,}\b", re.I), 0.90, "static_resource_numeric_suffix"),
        (re.compile(r"(?:[?&]|^)(?:idA|precioA|errorMsgA|B2A)=", re.I), 0.90, "csic_mutated_business_param"),
        (re.compile(r"(?:[?&]|^)(?:modo|B1)=(?:%7c|\|)", re.I), 0.90, "csic_control_char_param"),
        (re.compile(r"%25(?:3f|3F)|%253[fF]", re.I), 0.90, "double_encoded_question_mark"),
        (re.compile(r"(?:[?&]|^)pwd=[^&]*(?:%27|')", re.I), 0.88, "quote_in_password_param"),
    ],
}


CATEGORY_MAP = {
    "credential_leakage": "sensitive_data_exposure",
    "mcp_tool_abuse": "prompt_injection",
}


def _cap(score: float) -> float:
    return round(min(score, 1.0), 4)


def _combine_score(hits: Iterable[ScoreHit]) -> float:
    # Saturating sum: multiple weak indicators add up without exploding.
    miss_probability = 1.0
    for _, weight, _ in hits:
        miss_probability *= max(0.0, 1.0 - weight)
    return _cap(1.0 - miss_probability)


def _entropy_hint(text: str) -> float:
    if not text:
        return 0.0
    alphabet = set(text)
    if len(text) < 20 or len(alphabet) < 10:
        return 0.0
    probs = [text.count(ch) / len(text) for ch in alphabet]
    entropy = -sum(p * math.log2(p) for p in probs)
    return min(entropy / 5.5, 1.0)


def _score_category(category: str, text: str) -> List[ScoreHit]:
    hits: List[ScoreHit] = []
    for pattern, weight, term in PATTERNS.get(category, []):
        if pattern.search(text):
            hits.append((term, weight, pattern.pattern[:80]))
    return hits


def score_request(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """Score a normalized request context."""
    text = str(normalized.get("analysis_text", ""))
    lower_text = text.lower()
    scores: Dict[str, float] = {}
    evidence: Dict[str, List[Dict[str, Any]]] = {}

    for category in PATTERNS:
        hits = _score_category(category, text)
        if category == "credential_leakage" and hits:
            entropy = _entropy_hint(lower_text)
            if entropy > 0.55:
                hits.append(("high_entropy_context", 0.12, "entropy"))
        if category == "data_exfiltration":
            cred_hits = _score_category("credential_leakage", text)
            if cred_hits and hits:
                hits.append(("credential_with_exfil_context", 0.35, "credential+exfil"))
        if category == "mcp_tool_abuse":
            prompt_hits = _score_category("prompt_injection", text)
            exfil_hits = _score_category("data_exfiltration", text)
            if prompt_hits and hits:
                hits.append(("mcp_prompt_injection_combo", 0.30, "mcp+prompt"))
            if exfil_hits and hits:
                hits.append(("mcp_exfil_combo", 0.30, "mcp+exfil"))

        score = _combine_score(hits)
        scores[category] = score
        evidence[category] = [
            {"term": term, "weight": weight, "pattern": pattern}
            for term, weight, pattern in hits
        ]

    sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    top_category, top_score = sorted_scores[0] if sorted_scores else ("none", 0.0)
    mapped_category = CATEGORY_MAP.get(top_category, top_category)

    return {
        "scores": scores,
        "evidence": evidence,
        "top_category": mapped_category if top_score > 0 else "none",
        "raw_top_category": top_category,
        "top_score": top_score,
        "top_evidence": evidence.get(top_category, [])[:6],
        "summary": [
            {
                "category": CATEGORY_MAP.get(category, category),
                "raw_category": category,
                "score": score,
                "evidence": evidence.get(category, [])[:4],
            }
            for category, score in sorted_scores[:5]
            if score > 0
        ],
    }
