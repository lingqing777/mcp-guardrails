"""数据源 Processor 基类

每个数据源实现一个 Processor, 继承 DataSourceProcessor, 实现 process() 方法,
yield KnowledgeEntry 对象。build_kb.py 汇总所有 Processor 的输出。

约定:
  - Processor 只负责 "读取 + 清洗 + 结构化", 不负责去重和 embedding
  - 返回的 KnowledgeEntry text 字段必须非空、已去除首尾空白
  - metadata 至少包含 source 字段标注来源
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from ...schema import KnowledgeEntry


class DataSourceProcessor(ABC):
    """数据源处理器基类"""

    # 子类必须定义一个可读的来源标识 (用于 metadata.source)
    source_name: str = "unknown"

    def __init__(self, raw_dir: Path):
        """
        raw_dir: 该数据源的本地根目录, 如 waf2/rag/data/raw/payloadsallthethings/
        """
        self.raw_dir = Path(raw_dir)

    @abstractmethod
    def process(self) -> Iterator[KnowledgeEntry]:
        """遍历原始数据, yield KnowledgeEntry"""

    def is_available(self) -> bool:
        """原始数据目录是否存在"""
        return self.raw_dir.exists() and any(self.raw_dir.iterdir())
