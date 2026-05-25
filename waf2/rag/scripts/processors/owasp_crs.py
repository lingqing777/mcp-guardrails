"""OWASP Core Rule Set 数据源处理器

仓库结构:
    coreruleset/rules/
        REQUEST-XXX-APPLICATION-ATTACK-YYY.conf

SecRule 指令格式 (简化):
    SecRule <variables> "@rx <pattern>" \
        "id:<id>,phase:N,...,msg:'<description>',tag:'attack-sqli'"

策略:
  - 只解析包含 @rx (正则匹配) 的 SecRule
  - 从 pattern 本身提取 "攻击签名" 作为 text (规则本身已经是攻击模式的精华)
  - 从 msg 字段提取 description
  - 通过 tag 字段 (attack-sqli, attack-xss 等) 映射 category
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from .base import DataSourceProcessor
from ...schema import KnowledgeEntry


# CRS 文件名 → 默认 category (按 REQUEST-XXX 范围)
FILE_CATEGORY_HINTS: dict[str, str] = {
    "930": "path_traversal",      # LFI
    "931": "path_traversal",      # RFI
    "932": "command_injection",   # RCE
    "933": "command_injection",   # PHP
    "934": "command_injection",   # Generic
    "941": "xss",                 # XSS
    "942": "sql_injection",       # SQLi
    "943": "authentication_bypass", # Session Fixation
    "944": "command_injection",   # Java
    "950": "sensitive_data_exposure", # Data Leakages
}


# CRS tag → category 映射
TAG_TO_CATEGORY: dict[str, str] = {
    "attack-sqli": "sql_injection",
    "attack-xss": "xss",
    "attack-rce": "command_injection",
    "attack-lfi": "path_traversal",
    "attack-rfi": "path_traversal",
    "attack-disclosure": "sensitive_data_exposure",
    "attack-injection-php": "command_injection",
    "attack-injection-java": "command_injection",
    "attack-injection-generic": "command_injection",
    "attack-protocol": "ssrf",
    "attack-fixation": "authentication_bypass",
    "attack-xxe": "xxe",
    "attack-ssrf": "ssrf",
}


# CRS SecRule 中 @rx 后面是 pattern, 格式为:
#     @rx <pattern>"  "id:xxx, phase:N, ...,msg:'...'"
# 即 pattern 是从 @rx 之后到 `"  "` (引号-空格-引号) 之前的内容
# 也可能以 `"\n` (引号+换行) 结束
RX_PATTERN = re.compile(
    r'@rx\s+(.+?)(?:"\s+"|"\s*$|"\s*\n)',
    re.DOTALL | re.MULTILINE,
)
MSG_PATTERN = re.compile(r"msg:'([^']+)'")
TAG_PATTERN = re.compile(r"tag:'([^']+)'")


def _extract_secrules(content: str) -> list[str]:
    """把 .conf 文件内容切分成一条条完整的 SecRule 块"""
    # 先把续行 (行末 \) 合并
    content = re.sub(r"\\\s*\n\s*", " ", content)
    # 按 SecRule 开头切
    blocks = []
    current = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("SecRule ") or stripped.startswith("SecAction "):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _classify(block: str, filename: str) -> str:
    """根据 tag 和文件名确定 category"""
    # 优先用 tag
    for tag in TAG_PATTERN.findall(block):
        if tag in TAG_TO_CATEGORY:
            return TAG_TO_CATEGORY[tag]
    # 其次用文件名的 REQUEST-XXX 前缀
    m = re.search(r"REQUEST-(\d{3})-", filename)
    if m and m.group(1) in FILE_CATEGORY_HINTS:
        return FILE_CATEGORY_HINTS[m.group(1)]
    return "unknown"


class OwaspCrsProcessor(DataSourceProcessor):
    source_name = "OWASP-CRS"
    domain = "generic"

    def process(self) -> Iterator[KnowledgeEntry]:
        if not self.is_available():
            return

        rules_dir = self.raw_dir / "rules"
        if not rules_dir.is_dir():
            return

        for conf_file in sorted(rules_dir.glob("*.conf")):
            try:
                content = conf_file.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            # 折叠续行 (CRS 规则常用 \ 续行)
            flat = re.sub(r"\\\s*\n\s*", " ", content)

            # 直接抓所有 @rx "..." 片段
            patterns_found = RX_PATTERN.findall(flat)
            if not patterns_found:
                continue

            # 用 SecRule 起始位置切 block (用于推断每条规则对应的 pattern + tag + msg)
            rule_starts = [m.start() for m in re.finditer(r"\bSecRule\b", flat)]
            rule_starts.append(len(flat))

            for idx, rx_match in enumerate(RX_PATTERN.finditer(flat)):
                pattern = rx_match.group(1).strip()
                if len(pattern) < 5 or len(pattern) > 2000:
                    continue

                # 找到该 @rx 所在的 SecRule block (开头到下一个 SecRule)
                pos = rx_match.start()
                block_start = 0
                for rs in rule_starts:
                    if rs <= pos:
                        block_start = rs
                    else:
                        block_end = rs
                        break
                else:
                    block_end = len(flat)
                block = flat[block_start:block_end]

                category = _classify(block, conf_file.name)
                if category == "unknown":
                    continue

                msg_match = MSG_PATTERN.search(block)
                description = (
                    msg_match.group(1)
                    if msg_match
                    else f"CRS rule from {conf_file.name}"
                )

                try:
                    yield KnowledgeEntry(
                        text=pattern,
                        category=category,
                        metadata={
                            "source": self.source_name,
                            "description": description,
                        },
                    )
                except ValueError:
                    continue
