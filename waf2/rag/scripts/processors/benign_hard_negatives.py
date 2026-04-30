"""Benign hard-negative seed processor for the WAF2 knowledge evidence layer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .base import DataSourceProcessor
from ...schema import KnowledgeEntry


class BenignHardNegativeProcessor(DataSourceProcessor):
    """Load local benign examples that may resemble attacks but should not block."""

    source_name = "WAF2-Benign-Hard-Negatives"

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
            if not line or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            text = str(row.get("text") or row.get("body") or "").strip()
            if not text:
                continue
            category = str(row.get("category") or "unknown")
            metadata = dict(row.get("metadata") or {})
            metadata.setdefault("source", self.source_name)
            metadata.setdefault("description", row.get("description", "Benign hard-negative example"))
            metadata["evidence_type"] = "benign"
            if row.get("tag"):
                metadata.setdefault("tag", str(row["tag"]))

            try:
                yield KnowledgeEntry(text=text, category=category, metadata=metadata)
            except ValueError:
                continue
