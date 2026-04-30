"""知识库记录的数据结构和 metadata 映射表

每条知识库记录的统一结构 (对齐 waf2_proxy.py 的 ATTACK_CATEGORIES):

    {
        "text": "' OR 1=1 --",                    # 用于 embedding 的原始 payload
        "category": "sql_injection",               # WAF2 现有 11 种分类之一
        "metadata": {
            "cwe": "CWE-89",                       # CWE 编号
            "capec": "CAPEC-66",                   # CAPEC 编号
            "owasp": "A03:2021",                   # OWASP 映射
            "severity": "high",                    # critical / high / medium / low
            "description": "经典布尔型 SQL 注入",   # 人类可读说明
            "source": "PayloadsAllTheThings",       # 数据来源
        },
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


# WAF2 现有的 11 种攻击分类 (对齐 waf2_proxy.py 的 ATTACK_CATEGORIES)
VALID_CATEGORIES = {
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "ssrf",
    "xxe",
    "prompt_injection",
    "data_exfiltration",
    "sensitive_data_exposure",
    "authentication_bypass",
    "insecure_deserialization",
    "unknown",
}


# category → 默认 metadata 映射
# 当数据源只提供 payload 文本、没有明确归因时，用这个表补齐
CATEGORY_DEFAULTS: dict[str, dict[str, str]] = {
    "sql_injection": {
        "cwe": "CWE-89",
        "capec": "CAPEC-66",
        "owasp": "A03:2021",
        "severity": "high",
    },
    "xss": {
        "cwe": "CWE-79",
        "capec": "CAPEC-63",
        "owasp": "A03:2021",
        "severity": "medium",
    },
    "command_injection": {
        "cwe": "CWE-78",
        "capec": "CAPEC-88",
        "owasp": "A03:2021",
        "severity": "critical",
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "capec": "CAPEC-126",
        "owasp": "A01:2021",
        "severity": "high",
    },
    "ssrf": {
        "cwe": "CWE-918",
        "capec": "CAPEC-664",
        "owasp": "A10:2021",
        "severity": "high",
    },
    "xxe": {
        "cwe": "CWE-611",
        "capec": "CAPEC-201",
        "owasp": "A05:2021",
        "severity": "high",
    },
    "prompt_injection": {
        "cwe": "CWE-1039",
        "capec": "N/A",
        "owasp": "LLM01:2025",
        "severity": "high",
    },
    "data_exfiltration": {
        "cwe": "CWE-200",
        "capec": "CAPEC-116",
        "owasp": "A01:2021",
        "severity": "critical",
    },
    "sensitive_data_exposure": {
        "cwe": "CWE-200",
        "capec": "CAPEC-118",
        "owasp": "A02:2021",
        "severity": "high",
    },
    "authentication_bypass": {
        "cwe": "CWE-287",
        "capec": "CAPEC-115",
        "owasp": "A07:2021",
        "severity": "critical",
    },
    "insecure_deserialization": {
        "cwe": "CWE-502",
        "capec": "CAPEC-586",
        "owasp": "A08:2021",
        "severity": "critical",
    },
    "unknown": {
        "cwe": "N/A",
        "capec": "N/A",
        "owasp": "N/A",
        "severity": "medium",
    },
}


@dataclass
class KnowledgeEntry:
    """一条知识库记录"""

    text: str
    category: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.text or not self.text.strip():
            raise ValueError("text 不能为空")
        if self.category not in VALID_CATEGORIES:
            raise ValueError(f"category '{self.category}' 不在 VALID_CATEGORIES 中")

        # 补齐 metadata 默认值
        defaults = CATEGORY_DEFAULTS.get(self.category, CATEGORY_DEFAULTS["unknown"])
        for key, value in defaults.items():
            self.metadata.setdefault(key, value)
        self.metadata.setdefault("description", "")
        self.metadata.setdefault("source", "unknown")
        evidence_type = str(self.metadata.get("evidence_type", "attack")).lower()
        if evidence_type not in {"attack", "benign"}:
            raise ValueError("metadata.evidence_type 必须是 attack 或 benign")
        self.metadata["evidence_type"] = evidence_type

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KnowledgeEntry":
        return cls(
            text=data["text"],
            category=data["category"],
            metadata=dict(data.get("metadata", {})),
        )
