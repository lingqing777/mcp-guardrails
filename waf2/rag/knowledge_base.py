"""知识库加载 — 封装 ChromaDB 查询

容器启动时加载持久化的 ChromaDB 索引, 提供:
  - info(): 知识库元信息 (total_entries, by_category, built_at 等)
  - query(vector, top_k): 相似度检索

注意:
  - 这个类不做 embedding (由 OnnxEmbedder 负责),
    只负责在 ChromaDB 中检索已嵌入的向量
  - 启动时如果 ChromaDB 不存在或损坏, 要抛异常让上层决定降级
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np


@dataclass
class RetrievalResult:
    """单条检索结果"""

    text: str
    category: str
    metadata: dict[str, Any]
    score: float  # 相似度分数 (cosine similarity, 0-1, 越大越相似)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "category": self.category,
            "metadata": dict(self.metadata),
            "score": float(self.score),
        }


@dataclass
class KnowledgeBaseInfo:
    total_entries: int
    by_category: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)
    embedding_model: str = "unknown"
    vector_dim: int = 0
    built_at: str = ""
    version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entries": self.total_entries,
            "by_category": dict(self.by_category),
            "by_source": dict(self.by_source),
            "embedding_model": self.embedding_model,
            "vector_dim": self.vector_dim,
            "built_at": self.built_at,
            "version": self.version,
        }


class KnowledgeBase:
    """ChromaDB 持久化知识库"""

    COLLECTION_NAME = "waf2_attacks"

    def __init__(self, chroma_dir: Path, manifest_path: Path | None = None):
        try:
            import chromadb  # type: ignore
        except ImportError as exc:
            raise ImportError("需要安装 chromadb: pip install chromadb") from exc

        self.chroma_dir = Path(chroma_dir)
        if not self.chroma_dir.exists():
            raise FileNotFoundError(
                f"ChromaDB 目录不存在: {self.chroma_dir}; "
                f"请先运行 python -m waf2.rag.scripts.build_kb"
            )

        self._client = chromadb.PersistentClient(path=str(self.chroma_dir))
        self._collection = self._client.get_collection(self.COLLECTION_NAME)
        self._info = self._load_info(manifest_path)

    def _load_info(self, manifest_path: Path | None) -> KnowledgeBaseInfo:
        info = KnowledgeBaseInfo(total_entries=self._collection.count())

        if manifest_path and manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                info.by_category = dict(manifest.get("by_category", {}))
                info.by_source = dict(manifest.get("by_source", {}))
                info.embedding_model = manifest.get("embedding_model", "unknown")
                info.vector_dim = int(manifest.get("vector_dim", 0))
                info.built_at = manifest.get("built_at", "")
                info.version = manifest.get("version", "")
            except (json.JSONDecodeError, OSError):
                pass

        return info

    def info(self) -> KnowledgeBaseInfo:
        return self._info

    def query(
        self, vector: np.ndarray, top_k: int = 5, threshold: float = 0.5
    ) -> list[RetrievalResult]:
        """根据向量查询 top-k 相似记录, 过滤相似度 < threshold 的结果"""
        if vector.ndim == 1:
            query_embedding = vector.astype(np.float32).tolist()
        else:
            query_embedding = vector.astype(np.float32).squeeze().tolist()

        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )

        docs = (results.get("documents") or [[]])[0]
        metas = (results.get("metadatas") or [[]])[0]
        distances = (results.get("distances") or [[]])[0]

        out: list[RetrievalResult] = []
        for doc, meta, dist in zip(docs, metas, distances):
            # ChromaDB 默认返回 distance (cosine distance = 1 - cosine similarity)
            score = max(0.0, 1.0 - float(dist))
            if score < threshold:
                continue

            meta = dict(meta or {})
            category = meta.pop("category", "unknown")
            out.append(
                RetrievalResult(
                    text=str(doc or ""),
                    category=category,
                    metadata=meta,
                    score=score,
                )
            )
        return out
