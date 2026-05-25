"""PayloadsAllTheThings 数据源处理器

仓库结构:
    PayloadsAllTheThings/
        <Attack Type>/
            README.md             — 攻击说明和示例 payload
            Intruder/
                *.txt             — 每行一个 payload
                Images/           — 截图 (忽略)

策略:
  - 优先从 Intruder/*.txt 提取 payload (高质量、已分类)
  - 忽略 README.md、Images/ 等非 payload 文件
  - 目录名映射到 WAF2 的 11 种 category, 不在映射中的目录跳过
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .base import DataSourceProcessor
from ...schema import KnowledgeEntry


# PayloadsAllTheThings 目录名 → WAF2 category 映射
# 只保留能映射到现有 11 种分类的目录; 其他目录跳过
DIR_TO_CATEGORY: dict[str, str] = {
    "SQL Injection": "sql_injection",
    "NoSQL Injection": "sql_injection",
    "GraphQL Injection": "sql_injection",
    "LDAP Injection": "sql_injection",
    "ORM Leak": "sql_injection",
    "XSS Injection": "xss",
    "CSV Injection": "xss",
    "CSS Injection": "xss",
    "CRLF Injection": "xss",
    "DOM Clobbering": "xss",
    "Command Injection": "command_injection",
    "Server Side Template Injection": "command_injection",
    "Server Side Include Injection": "command_injection",
    "Directory Traversal": "path_traversal",
    "Client Side Path Traversal": "path_traversal",
    "File Inclusion": "path_traversal",
    "Server Side Request Forgery": "ssrf",
    "XML External Entity": "xxe",
    "XXE Injection": "xxe",
    "XPATH Injection": "xxe",
    "Prompt Injection": "prompt_injection",
    "Insecure Deserialization": "insecure_deserialization",
    "Web Cache Deception": "data_exfiltration",
    "Request Smuggling": "data_exfiltration",
    "API Key Leaks": "sensitive_data_exposure",
    "Insecure Source Code Management": "sensitive_data_exposure",
    "JSON Web Token": "authentication_bypass",
    "SAML Injection": "authentication_bypass",
    "OAuth Misconfiguration": "authentication_bypass",
    "Account Takeover": "authentication_bypass",
    "Type Juggling": "authentication_bypass",
}


# Intruder txt 文件中一般每行一个 payload, 过滤这些明显非 payload 的行
def _is_valid_payload(line: str) -> bool:
    line = line.strip()
    if not line:
        return False
    if line.startswith("#"):  # 注释
        return False
    if len(line) < 3:
        return False
    if len(line) > 2000:  # 过长的 payload 可能是误匹配
        return False
    return True


# 单个字典文件最多取多少条 payload
# PayloadsAllTheThings 里有部分大字典 (如 Directory Traversal 的 deepdive),
# 对 RAG 贡献有限但会压倒其他数据; 采样上限避免类别严重失衡
PER_FILE_LIMIT = 150


class PayloadsAllTheThingsProcessor(DataSourceProcessor):
    source_name = "PayloadsAllTheThings"
    domain = "generic"

    def process(self) -> Iterator[KnowledgeEntry]:
        if not self.is_available():
            return

        for attack_dir in sorted(self.raw_dir.iterdir()):
            if not attack_dir.is_dir():
                continue

            category = DIR_TO_CATEGORY.get(attack_dir.name)
            if not category:
                continue  # 不在映射表中的攻击类型跳过

            # 遍历 Intruder 子目录的 txt 文件
            intruder_dir = attack_dir / "Intruder"
            if intruder_dir.is_dir():
                yield from self._process_intruder(intruder_dir, category, attack_dir.name)

            # 从 README.md 提取代码块中的 payload (可选增强)
            readme = attack_dir / "README.md"
            if readme.is_file():
                yield from self._process_readme(readme, category, attack_dir.name)

    def _process_intruder(
        self, intruder_dir: Path, category: str, attack_name: str
    ) -> Iterator[KnowledgeEntry]:
        for txt_file in intruder_dir.rglob("*.txt"):
            try:
                content = txt_file.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            emitted = 0
            for line in content.splitlines():
                if emitted >= PER_FILE_LIMIT:
                    break
                line = line.strip()
                if not _is_valid_payload(line):
                    continue

                yield KnowledgeEntry(
                    text=line,
                    category=category,
                    metadata={
                        "source": self.source_name,
                        "domain": self.domain,
                        "description": f"{attack_name} payload from {txt_file.name}",
                    },
                )
                emitted += 1

    def _process_readme(
        self, readme: Path, category: str, attack_name: str
    ) -> Iterator[KnowledgeEntry]:
        """从 README.md 的 ``` 代码块中提取 payload"""
        try:
            content = readme.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            return

        in_code_block = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue
            if not in_code_block:
                continue
            if not _is_valid_payload(stripped):
                continue
            # README 中的代码块多数是示例 payload
            yield KnowledgeEntry(
                text=stripped,
                category=category,
                metadata={
                    "source": self.source_name,
                    "domain": self.domain,
                    "description": f"{attack_name} example from README",
                },
            )
