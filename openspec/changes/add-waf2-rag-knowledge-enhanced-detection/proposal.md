## Why

WAF2 当前的 LLM 检测完全依赖模型自身的安全知识——prompt 是硬编码模板，LLM 凭训练数据判断 BLOCK/PASS。遇到变体 payload、新型攻击手法或小众注入模式时，检出率受限于模型知识边界。学术界已有多篇论文验证 RAG 在安全检测场景的增益（Springer RAG+Self-Ranking、PNNL CyRAG/GraphCyRAG、CVE-KGRAG），但目前没有开源项目将 RAG 直接嵌入 WAF 实时检测管线。这是一个有学术支撑、无现成实现的创新点，适合作为信安作品赛的核心差异化能力。

## What Changes

- 新增 RAG 知识增强层：在 WAF2 的静态规则预筛查之后、LLM 判断之前，插入一步向量检索，从攻击知识库中检索与当前请求最相似的已知攻击案例，作为上下文塞入 LLM prompt
- 新增攻击知识库：预构建结构化知识库，数据来源包括 PayloadsAllTheThings（~4000 条攻击 payload）、OWASP CRS 规则（~800 条）、CWE/CAPEC 映射（~250 条）、OWASP Prompt Injection cheat sheets（~300 条），每条记录包含 payload 文本、攻击分类、CWE/CAPEC/OWASP 映射、严重级别和描述
- 新增本地 Embedding 能力：容器内置 ONNX 格式的轻量 embedding 模型（all-MiniLM-L6-v2，~22MB），用于将请求文本和知识库条目转换为向量，零外部依赖
- 新增向量存储：使用 ChromaDB 进程内模式存储和检索向量索引，知识库预构建后打包进 Docker 镜像
- 增强 LLM prompt：REQUEST_ANALYSIS_PROMPT 和 RESPONSE_ANALYSIS_PROMPT 新增检索结果上下文段，LLM 可参考已知攻击案例做出更准确的判断和 CWE/CAPEC 归因
- 新增知识库构建工具：提供 `build_kb.py` 脚本，从原始数据源清洗、结构化、embedding、写入 ChromaDB
- 新增 RAG 配置项：`RAG_ENABLED` 开关，可通过环境变量或 Dashboard 启用/禁用
- Docker 镜像变更：Dockerfile 新增 onnxruntime、chromadb 依赖及预构建知识库，镜像增量约 170MB（从 ~140MB 增至 ~310MB）

## Capabilities

### New Capabilities

- `waf2-rag`: WAF2 的 RAG 知识增强检测能力，包括攻击知识库构建、本地 embedding、向量检索、prompt 增强的完整管线
- `waf2-knowledge-base`: 攻击知识库的数据结构、数据源、构建流程和预构建打包机制

### Modified Capabilities

- `waf2`: 检测流程从"静态规则 → LLM 判断"变为"静态规则 → RAG 检索 → LLM 判断"三阶段；新增 RAG 相关配置项和 API 端点；Docker 镜像依赖变更
- `dashboard`: 新增 RAG 状态展示（知识库条目数、检索命中情况）和 RAG 开关配置

## Impact

- **代码**
  - `waf2/waf2_proxy.py` — 新增 RAG 检索步骤，修改 `analyze_request()` 和 `analyze_response()` 在调用 `call_llm()` 前插入检索上下文；修改 prompt 模板新增 `{retrieved_context}` 占位符
  - `waf2/rag/` — 新增目录，包含 `engine.py`（检索引擎）、`embedder.py`（ONNX embedding 封装）、`knowledge_base.py`（知识库加载）
  - `waf2/rag/data/` — 预处理的知识库数据（JSONL）和预构建的 ChromaDB 向量索引
  - `waf2/scripts/build_kb.py` — 知识库构建脚本（开发/维护用）
- **Docker**
  - `waf2/Dockerfile` — 新增 `onnxruntime`、`chromadb`、`numpy` 依赖安装；新增 ONNX 模型下载步骤；COPY 预构建知识库
  - `waf2/requirements.txt` — 新增依赖项
  - `docker-compose.yml` — 新增 `RAG_ENABLED` 环境变量
  - 镜像体积从 ~140MB 增至 ~310MB
- **API**
  - `GET /waf2/config` — 响应新增 `rag_enabled`、`knowledge_base_size` 字段
  - `POST /waf2/config` — 新增 `rag_enabled` 可选字段
  - `GET /waf2/stats` — 响应新增 `rag_queries`、`rag_avg_latency_ms` 字段
  - `GET /waf2/dashboard` — 响应新增 `rag` 段落
  - 不新增独立路由，复用现有 `/waf2/*` 端点体系
- **Dashboard**
  - WAF2 配置区域新增 RAG 开关
  - WAF2 统计区域新增知识库状态和检索统计
  - 不影响现有 5 秒刷新机制，RAG 统计随现有 stats 接口一并返回
- **路由注册顺序**
  - 不变，所有新增 API 字段通过现有 `/waf2/*` 端点返回
- **参考资料**
  - 数据清洗流程：参考 CVE-KGRAG (github.com/Yuning-J/CVE-KGRAG)
  - 知识库组织结构：参考 PNNL CyRAG 的 CWE→CAPEC→ATT&CK 映射链
  - Prompt 增强策略：参考 Springer RAG+Self-Ranking 论文 (10.1007/s10664-025-10743-w)
  - 效果评估基准：CSIC 2010 HTTP Dataset
