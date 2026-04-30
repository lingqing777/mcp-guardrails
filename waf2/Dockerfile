FROM python:3.11-slim

WORKDIR /app

# Python 依赖 (含 RAG 运行时: onnxruntime + chromadb + tokenizers + numpy)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# WAF2 主程序及依赖模块
COPY waf2_proxy.py normalization.py local_attack_score.py risk_router.py .

# RAG 模块代码 (.dockerignore 已排除 rag/scripts/, 只 COPY 运行时必要部分)
COPY rag/__init__.py rag/schema.py rag/embedder.py \
     rag/knowledge_base.py rag/engine.py /app/rag/

# RAG 数据资产 (镜像预置, 实现一键启动)
#   - model/        ONNX 模型 (~87M)
#   - chroma_db/    ChromaDB 向量索引 (~15M)
#   - manifest.json 版本元信息
COPY rag/data/model /app/rag/data/model
COPY rag/data/chroma_db /app/rag/data/chroma_db
COPY rag/data/manifest.json /app/rag/data/manifest.json

EXPOSE 8081

CMD ["python", "waf2_proxy.py"]
