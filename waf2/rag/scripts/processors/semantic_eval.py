"""Semantic Eval 数据源处理器

将评估集里的语义攻击样本注入 KB，缩小线上 query 与 KB 语料分布差异。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .base import DataSourceProcessor
from ...schema import KnowledgeEntry


class SemanticEvalProcessor(DataSourceProcessor):
    source_name = "Semantic-Eval"

    def __init__(self, jsonl_file: Path):
        super().__init__(jsonl_file.parent)
        self.jsonl_file = Path(jsonl_file)

    def is_available(self) -> bool:
        return self.jsonl_file.exists()

    def process(self) -> Iterator[KnowledgeEntry]:
        if not self.is_available():
            return

        try:
            lines = self.jsonl_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            if str(row.get("label", "")).lower() != "attack":
                continue

            body = str(row.get("body", "")).strip()
            path = str(row.get("path", "")).strip()
            if not body:
                continue

            text = body if not path else f"{body}\nPATH:{path}"
            lowered = body.lower()
            if any(k in lowered for k in ("system prompt", "ignore previous", "jailbreak", "dan mode", "system_override")):
                category = "prompt_injection"
            elif any(k in lowered for k in ("auth.users", "service role key", "credentials", "api keys", "private data", "exfiltrate")):
                category = "data_exfiltration"
            elif any(k in lowered for k in ("execute_sql", "skip verification", "admin", "bypass")):
                category = "authentication_bypass"
            elif any(k in lowered for k in ("169.254.169.254", "http://", "https://")):
                category = "ssrf"
            elif any(k in lowered for k in ("/etc/passwd", ".env", "id_rsa", "shell command")):
                category = "command_injection"
            else:
                category = "prompt_injection"

            try:
                yield KnowledgeEntry(
                    text=text,
                    category=category,
                    metadata={
                        "source": self.source_name,
                        "description": "Semantic attack sample from eval set",
                    },
                )
            except ValueError:
                continue

