"""RAG 引擎 — WAF2 运行时的对外入口

组合 OnnxEmbedder + KnowledgeBase, 对 waf2_proxy.py 暴露一个简洁的 retrieve() 接口。

典型用法:
    engine = RagEngine.from_default_paths()
    results = engine.retrieve("1' OR 1=1 --")
    # results: [{"text": "...", "category": "sql_injection", ...}, ...]

设计约束:
  - 初始化失败时允许抛异常, 由 waf2_proxy 决定是降级还是禁用 RAG
  - retrieve() 内部异常不抛, 返回空列表 (由调用方记录 stats['rag_errors'])
  - 线程安全: ChromaDB 和 onnxruntime 都支持并发查询
  - aretrieve() (async): 用 asyncio.to_thread 包装,使 ONNX 推理与 ChromaDB 查询
    不阻塞调用方的事件循环 (improve-waf2-concurrency-for-rq5)
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .embedder import OnnxEmbedder
from .knowledge_base import KnowledgeBase, RetrievalResult


log = logging.getLogger(__name__)


RAG_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_MODEL_DIR = RAG_DIR / "model"
DEFAULT_CHROMA_DIR = RAG_DIR / "chroma_db"
DEFAULT_MANIFEST = RAG_DIR / "manifest.json"


@dataclass
class RagStats:
    queries: int = 0
    errors: int = 0
    empty_results: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        if self.queries == 0:
            return 0.0
        return self.total_latency_ms / self.queries

    def to_dict(self) -> dict[str, float | int]:
        return {
            "queries": self.queries,
            "errors": self.errors,
            "empty_results": self.empty_results,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }

    def reset(self) -> None:
        self.queries = 0
        self.errors = 0
        self.empty_results = 0
        self.total_latency_ms = 0.0


class RagEngine:
    def __init__(
        self,
        embedder: OnnxEmbedder,
        knowledge_base: KnowledgeBase,
        top_k: int = 5,
        threshold: float = 0.5,
        domain_filter: str | None = None,
    ):
        self.embedder = embedder
        self.knowledge_base = knowledge_base
        self.top_k = top_k
        self.threshold = threshold
        self.domain_filter = domain_filter
        self.stats = RagStats()

    @classmethod
    def from_default_paths(
        cls,
        model_dir: Path = DEFAULT_MODEL_DIR,
        chroma_dir: Path = DEFAULT_CHROMA_DIR,
        manifest_path: Path = DEFAULT_MANIFEST,
        top_k: int = 5,
        threshold: float = 0.5,
        domain_filter: str | None = None,
    ) -> "RagEngine":
        embedder = OnnxEmbedder(model_dir)
        kb = KnowledgeBase(chroma_dir, manifest_path=manifest_path)
        return cls(embedder, kb, top_k=top_k, threshold=threshold, domain_filter=domain_filter)

    def retrieve(self, text: str) -> list[RetrievalResult]:
        """检索与 text 最相似的 top_k 条已知攻击 (双路召回 + 阈值回退)。"""
        if not text or not text.strip():
            return []

        start = time.perf_counter()
        try:
            merged: list[RetrievalResult] = []
            # 路由1: 原始输入
            vector = self.embedder.encode_one(text)
            merged.extend(self.knowledge_base.query(vector, top_k=self.top_k, threshold=self.threshold, domain_filter=self.domain_filter))

            # 路由2: 仅内容段，减少 METHOD/PATH 噪声
            if "CONTENT:" in text:
                content = text.split("CONTENT:", 1)[1].split("\nPATH:", 1)[0].strip()
                if content:
                    vector2 = self.embedder.encode_one(content)
                    merged.extend(self.knowledge_base.query(vector2, top_k=self.top_k, threshold=self.threshold, domain_filter=self.domain_filter))

            # 去重并按 score 排序
            uniq: dict[tuple[str, str], RetrievalResult] = {}
            for r in merged:
                key = (r.text, r.category)
                if key not in uniq or r.score > uniq[key].score:
                    uniq[key] = r
            results = sorted(uniq.values(), key=lambda x: x.score, reverse=True)[: self.top_k]

            # 阈值回退：无结果时做低阈值兜底，优先保障有可参考上下文
            if not results:
                fallback = max(0.35, self.threshold - 0.15)
                results = self.knowledge_base.query(vector, top_k=self.top_k, threshold=fallback, domain_filter=self.domain_filter)
        except Exception as exc:
            self.stats.errors += 1
            log.warning("[RagEngine] 检索失败: %s", exc)
            return []
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.stats.total_latency_ms += elapsed_ms
            self.stats.queries += 1

        if not results:
            self.stats.empty_results += 1

        return results

    async def aretrieve(self, text: str) -> list[RetrievalResult]:
        """异步包装,等价于 retrieve() 但跑在线程池避免阻塞事件循环。

        ONNX 推理与 ChromaDB 查询都是同步 CPU/IO,搬到 asyncio.to_thread 后:
          - 主事件循环在 ONNX encode / Chroma query 期间可以继续调度其它请求
          - 调用语义、返回值、内部 stats 累积全部与同步版一致
        """
        return await asyncio.to_thread(self.retrieve, text)

    def info(self) -> dict[str, Any]:
        kb_info = self.knowledge_base.info()
        return {
            **kb_info.to_dict(),
            "top_k": self.top_k,
            "threshold": self.threshold,
        }


def format_retrieved_context(results: list[RetrievalResult]) -> str:
    """将检索结果格式化为 LLM prompt 中的上下文段"""
    if not results:
        return "(无相似案例，凭自身知识判断)"

    lines: list[str] = []
    for i, r in enumerate(results, start=1):
        cwe = r.metadata.get("cwe", "N/A")
        capec = r.metadata.get("capec", "N/A")
        severity = r.metadata.get("severity", "medium")
        description = r.metadata.get("description", "")
        source = r.metadata.get("source", "unknown")
        evidence_type = (r.evidence_type or r.metadata.get("evidence_type", "attack") or "attack").lower()
        evidence_label = "BENIGN_HARD_NEGATIVE" if evidence_type == "benign" else "ATTACK"
        evidence_id = r.evidence_id or f"kb#{i}"
        # 限制单条文本长度避免撑爆 prompt
        text_display = r.text[:200] + ("..." if len(r.text) > 200 else "")

        header = (
            f"{i}. [{evidence_label}/{r.category}] id={evidence_id} "
            f"score={r.score:.3f} source={source} :: {text_display} "
            f"({cwe}, {capec}, severity: {severity})"
        )
        lines.append(header)
        if description:
            lines.append(f"   说明: {description[:200]}")
    return "\n".join(lines)
