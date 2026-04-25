"""知识库构建脚本 — 从原始数据源到 ChromaDB 索引的完整流水线

用法:
    # 只做数据清洗 + 写 JSONL (无需 embedding 依赖)
    python -m waf2.rag.scripts.build_kb --phase clean

    # 完整流程: 清洗 → embedding → 写入 ChromaDB
    python -m waf2.rag.scripts.build_kb --phase all

    # 只做向量化 (需要已有 payloads.jsonl 和 ONNX 模型)
    python -m waf2.rag.scripts.build_kb --phase embed

依赖:
    clean 阶段: 仅标准库 + Python 3.10+
    embed 阶段: onnxruntime, chromadb, numpy, tokenizers
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Iterator

# 允许 python -m waf2.rag.scripts.build_kb 和直接脚本运行
HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[3]  # .../mcp-guardrails (build_kb.py -> scripts -> rag -> waf2 -> mcp-guardrails)
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from waf2.rag.schema import KnowledgeEntry  # noqa: E402
from waf2.rag.scripts.processors import (  # noqa: E402
    OwaspCrsProcessor,
    PayloadsAllTheThingsProcessor,
    PromptInjectionProcessor,
    SemanticEvalProcessor,
)


RAG_DIR = PROJECT_ROOT / "waf2" / "rag"
RAW_DIR = RAG_DIR / "data" / "raw"
PROCESSED_DIR = RAG_DIR / "data" / "processed"
CHROMA_DIR = RAG_DIR / "data" / "chroma_db"
MODEL_DIR = RAG_DIR / "data" / "model"
MANIFEST_PATH = RAG_DIR / "data" / "manifest.json"
PAYLOADS_JSONL = PROCESSED_DIR / "payloads.jsonl"

MANIFEST_VERSION = "0.1.0"
CHROMA_COLLECTION = "waf2_attacks"


# ==================== 阶段 1: 清洗 ====================


def _build_processors() -> list:
    return [
        PayloadsAllTheThingsProcessor(RAW_DIR / "payloadsallthethings"),
        OwaspCrsProcessor(RAW_DIR / "owasp-crs"),
        PromptInjectionProcessor(RAW_DIR / "prompt-injection"),
        # ⚠️ 已禁用 SemanticEvalProcessor: 它会把评估集 (eval/semantic_only.jsonl)
        # 注入到 KB, 而 eval_rag.py 评估时也读同一个文件 → 数据泄漏, F1 虚高。
        # 如需把语义攻击样本入 KB, 请用独立的种子文件 (不能复用评估集)。
        # SemanticEvalProcessor(RAG_DIR / "eval" / "semantic_only.jsonl"),
    ]


def _iter_all_entries() -> Iterator[KnowledgeEntry]:
    for proc in _build_processors():
        try:
            yield from proc.process()
        except Exception as exc:  # 单个 processor 失败不阻断其他
            print(f"[build_kb] ⚠️  {proc.__class__.__name__} 失败: {exc}", file=sys.stderr)


def clean_phase() -> dict:
    """读取所有数据源 → 去重 → 写入 JSONL, 返回统计信息"""
    print(f"[build_kb] 🚿 清洗阶段开始")
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    category_counter: Counter = Counter()
    source_counter: Counter = Counter()
    total = 0
    dropped = 0

    with PAYLOADS_JSONL.open("w", encoding="utf-8") as fh:
        for entry in _iter_all_entries():
            key = f"{entry.category}::{entry.text}"
            if key in seen:
                dropped += 1
                continue
            seen.add(key)
            fh.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
            category_counter[entry.category] += 1
            source_counter[entry.metadata.get("source", "unknown")] += 1
            total += 1

    print(f"[build_kb] ✅ 清洗完成: {total} 条记录, 去重跳过 {dropped} 条")
    print(f"[build_kb] 📊 按类别分布:")
    for cat, count in sorted(category_counter.items(), key=lambda x: -x[1]):
        print(f"           {cat:30s}  {count:5d}")
    print(f"[build_kb] 📊 按数据源分布:")
    for src, count in sorted(source_counter.items(), key=lambda x: -x[1]):
        print(f"           {src:30s}  {count:5d}")
    print(f"[build_kb] 📁 输出: {PAYLOADS_JSONL}")

    return {
        "total": total,
        "dropped": dropped,
        "by_category": dict(category_counter),
        "by_source": dict(source_counter),
    }


# ==================== 阶段 2: 向量化 + 索引 ====================


def embed_phase(stats_from_clean: dict | None = None) -> dict:
    """读 JSONL → embedding → 写 ChromaDB"""
    print(f"[build_kb] 🧮 向量化阶段开始")

    try:
        import chromadb  # type: ignore
    except ImportError:
        raise SystemExit("❌ 请先安装依赖: pip install chromadb onnxruntime numpy tokenizers")

    if not PAYLOADS_JSONL.exists():
        raise SystemExit(f"❌ 未找到 {PAYLOADS_JSONL}, 请先运行 --phase clean")

    # 懒加载 embedder (避免 clean 阶段也依赖 onnxruntime)
    from waf2.rag.embedder import OnnxEmbedder  # noqa: E402

    if not MODEL_DIR.exists() or not any(MODEL_DIR.iterdir()):
        raise SystemExit(
            f"❌ 未找到 ONNX 模型: {MODEL_DIR}\n"
            f"   请先运行 python -m waf2.rag.scripts.export_onnx"
        )

    embedder = OnnxEmbedder(MODEL_DIR)
    print(f"[build_kb]    ONNX 模型已加载: {embedder.model_name}, 维度 {embedder.vector_dim}")

    # 清空旧的 ChromaDB (幂等重建)
    if CHROMA_DIR.exists():
        import shutil
        shutil.rmtree(CHROMA_DIR)
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.create_collection(
        name=CHROMA_COLLECTION,
        metadata={"hnsw:space": "cosine"},
    )

    # 批量读取 + 向量化 + 插入
    BATCH = 128
    entries: list[KnowledgeEntry] = []
    with PAYLOADS_JSONL.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entries.append(KnowledgeEntry.from_dict(json.loads(line)))

    total = len(entries)
    print(f"[build_kb]    待向量化: {total} 条")

    start = time.time()
    for i in range(0, total, BATCH):
        batch = entries[i : i + BATCH]
        texts = [e.text for e in batch]
        vectors = embedder.encode(texts)
        ids = [f"entry-{i + j}" for j in range(len(batch))]
        # ChromaDB 要求 metadata 扁平化
        metadatas = []
        for e in batch:
            md = {"category": e.category}
            for k, v in e.metadata.items():
                md[k] = v if isinstance(v, (str, int, float, bool)) else str(v)
            metadatas.append(md)
        collection.add(ids=ids, embeddings=vectors.tolist(), documents=texts, metadatas=metadatas)
        done = min(i + BATCH, total)
        print(f"[build_kb]    向量化进度: {done}/{total} ({done/total*100:.1f}%)")

    elapsed = time.time() - start
    print(f"[build_kb] ✅ 向量化完成: {total} 条, 耗时 {elapsed:.1f}s")
    print(f"[build_kb] 📁 索引: {CHROMA_DIR}")

    return {
        "total": total,
        "elapsed_sec": elapsed,
        "vector_dim": embedder.vector_dim,
        "embedding_model": embedder.model_name,
    }


# ==================== Manifest ====================


def _git_head(repo_dir: Path) -> str:
    head_file = repo_dir / ".git" / "HEAD"
    if not head_file.exists():
        return "unknown"
    try:
        content = head_file.read_text(encoding="utf-8").strip()
        if content.startswith("ref:"):
            ref = content[4:].strip()
            ref_file = repo_dir / ".git" / ref
            if ref_file.exists():
                return ref_file.read_text(encoding="utf-8").strip()[:12]
        return content[:12]
    except OSError:
        return "unknown"


def write_manifest(clean_stats: dict, embed_stats: dict | None) -> None:
    manifest = {
        "version": MANIFEST_VERSION,
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_entries": clean_stats.get("total", 0),
        "by_category": clean_stats.get("by_category", {}),
        "by_source": clean_stats.get("by_source", {}),
        "sources": {
            "payloadsallthethings": _git_head(RAW_DIR / "payloadsallthethings"),
            "owasp_crs": _git_head(RAW_DIR / "owasp-crs"),
        },
        "embedding_model": (embed_stats or {}).get("embedding_model", ""),
        "vector_dim": (embed_stats or {}).get("vector_dim", 0),
        "collection": CHROMA_COLLECTION,
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[build_kb] 📄 manifest: {MANIFEST_PATH}")


# ==================== CLI ====================


def main() -> None:
    parser = argparse.ArgumentParser(description="WAF2 RAG 知识库构建")
    parser.add_argument(
        "--phase",
        choices=["clean", "embed", "all"],
        default="all",
        help="执行阶段: clean=只清洗, embed=只向量化, all=全流程",
    )
    args = parser.parse_args()

    overall_start = time.time()
    clean_stats: dict = {}
    embed_stats: dict | None = None

    if args.phase in ("clean", "all"):
        clean_stats = clean_phase()

    if args.phase in ("embed", "all"):
        # 如果只跑 embed, 从已有 JSONL 读出统计供 manifest 使用
        if not clean_stats:
            category_counter: Counter = Counter()
            source_counter: Counter = Counter()
            total = 0
            if PAYLOADS_JSONL.exists():
                with PAYLOADS_JSONL.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip():
                            d = json.loads(line)
                            category_counter[d["category"]] += 1
                            source_counter[d.get("metadata", {}).get("source", "unknown")] += 1
                            total += 1
            clean_stats = {
                "total": total,
                "by_category": dict(category_counter),
                "by_source": dict(source_counter),
            }
        embed_stats = embed_phase(clean_stats)

    write_manifest(clean_stats, embed_stats)
    print(f"[build_kb] 🏁 全部完成, 总耗时 {time.time() - overall_start:.1f}s")


if __name__ == "__main__":
    main()
