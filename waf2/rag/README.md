# WAF2 RAG 模块

## 目录结构

```
rag/
├── __init__.py
├── schema.py              知识库记录数据结构 (KnowledgeEntry + 分类映射)
├── embedder.py            ONNX embedding 运行时封装
├── knowledge_base.py      ChromaDB 知识库加载和查询
├── engine.py              RAG 引擎入口 (组合 embedder + kb)
├── scripts/
│   ├── build_kb.py        知识库构建主脚本
│   ├── export_onnx.py     导出 all-MiniLM-L6-v2 为 ONNX
│   ├── eval_rag.py        RAG 效果评估 (CSIC 2010)
│   └── processors/        各数据源处理器
└── data/
    ├── raw/               原始数据源 (git 忽略, 外部克隆)
    ├── processed/         清洗后的 JSONL
    ├── model/             ONNX embedding 模型
    ├── chroma_db/         ChromaDB 持久化索引
    └── manifest.json      知识库元信息
```

## 构建流程

### 1. 拉取原始数据

```bash
cd waf2/rag/data/raw
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings payloadsallthethings
git clone --depth 1 https://github.com/coreruleset/coreruleset owasp-crs
```

`prompt-injection/` 目录是可选的, 用户手动放 txt 或 md 文件即可追加 prompt injection payload。
未提供时使用代码里内置的 20 条种子 payload。

### 2. 搭建开发虚拟环境

```bash
# 在项目根目录
python3 -m venv waf2/rag/.venv

# 运行时依赖 (也是容器内依赖)
waf2/rag/.venv/bin/pip install onnxruntime chromadb tokenizers numpy

# 开发时额外依赖 (只用于导出 ONNX)
waf2/rag/.venv/bin/pip install "optimum[onnxruntime]" sentence-transformers transformers
```

### 3. 导出 ONNX 模型

```bash
waf2/rag/.venv/bin/python -m waf2.rag.scripts.export_onnx
```

输出 `waf2/rag/data/model/` 三个文件: `model.onnx`, `tokenizer.json`, `config.json`。

### 4. 构建知识库

```bash
# 一步到位 (清洗 + embedding + 写入 ChromaDB)
waf2/rag/.venv/bin/python -m waf2.rag.scripts.build_kb --phase all

# 或分步
waf2/rag/.venv/bin/python -m waf2.rag.scripts.build_kb --phase clean
waf2/rag/.venv/bin/python -m waf2.rag.scripts.build_kb --phase embed
```

完成后 `waf2/rag/data/` 下会生成 `chroma_db/` 目录和 `manifest.json` 元信息。

## 扩展新数据源

在 `scripts/processors/` 新增一个 processor 类, 继承 `DataSourceProcessor`:

```python
from .base import DataSourceProcessor
from ...schema import KnowledgeEntry


class MyProcessor(DataSourceProcessor):
    source_name = "MySource"

    def process(self):
        for entry in _read_data(self.raw_dir):
            yield KnowledgeEntry(
                text=entry.payload,
                category="sql_injection",  # 必须是 VALID_CATEGORIES 之一
                metadata={
                    "source": self.source_name,
                    "description": entry.description,
                },
            )
```

然后在 `scripts/processors/__init__.py` 和 `build_kb._build_processors()` 中注册。

## 容器内集成

容器启动时 `waf2_proxy.py` 会自动加载 RAG:

```python
from rag.engine import RagEngine
rag_engine = RagEngine.from_default_paths()
```

加载失败不会阻塞 WAF2 启动, 只是禁用 RAG 功能。

RAG 开关:
- 环境变量: `RAG_ENABLED=true|false` (默认 true)
- 环境变量: `RAG_SCOPE=request|all` (默认 request, all 表示响应也做 RAG)
- 运行时通过 `POST /waf2/config` 更新 `rag_enabled` 和 `rag_scope`

## 评估

```bash
# 下载 CSIC 2010 数据集到 waf2/rag/eval/csic2010/
# (见 README 主文件的链接)

waf2/rag/.venv/bin/python -m waf2.rag.scripts.eval_rag --waf2 http://localhost:8081
```

输出 `waf2/rag/eval/results.md`, 含 RAG on/off 的 precision/recall/F1/FPR 对比。

## 参考资料

- Springer 论文 (RAG + Self-Ranking): https://link.springer.com/article/10.1007/s10664-025-10743-w
- PNNL CyRAG: https://www.pnnl.gov/publications/retrieval-augmented-generation-robust-cyber-defense
- CVE-KGRAG: https://github.com/Yuning-J/CVE-KGRAG
- CSIC 2010 数据集: https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks
- HTTP2vec: https://arxiv.org/pdf/2108.01763
- ControlNet (RAG 防火墙): https://arxiv.org/html/2504.09593v1
