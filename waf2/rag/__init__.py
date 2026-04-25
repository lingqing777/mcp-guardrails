"""WAF2 RAG — 知识增强语义检测模块

模块结构:
    embedder.py       — ONNX embedding 模型封装
    knowledge_base.py — ChromaDB 知识库加载和查询
    engine.py         — 对外暴露的 RAG 引擎入口
    scripts/          — 开发时构建脚本 (build_kb.py, export_onnx.py, eval_rag.py)
    data/             — 模型文件、知识库数据、ChromaDB 持久化目录
"""
