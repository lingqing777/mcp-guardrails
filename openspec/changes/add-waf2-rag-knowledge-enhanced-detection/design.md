## Context

WAF2 当前是一个 Python/FastAPI 反向代理（`waf2/waf2_proxy.py`，~634 行），运行在 Docker 容器中（`python:3.11-slim`，~140MB）。检测管线为两阶段：静态正则预筛查 `static_rule_check()` → LLM 语义判断 `analyze_request()`/`analyze_response()` → `call_llm()`。

LLM 判断依赖两个硬编码 prompt 模板（`REQUEST_ANALYSIS_PROMPT` 和 `RESPONSE_ANALYSIS_PROMPT`），模型凭自身训练知识输出 `PASS` 或 `BLOCK|<category>|<reason>`。没有外部知识注入，遇到变体 payload 或新攻击手法时检出率受限。

现有缓存机制（MD5 哈希，500 条，5min TTL）和多 LLM Provider 支持（OpenAI/Anthropic/Gemini 三种格式）不受本次改动影响。

## Goals / Non-Goals

**Goals:**

- 在 WAF2 检测管线中插入 RAG 知识增强层，让 LLM 判断时能参考已知攻击案例
- 构建高质量攻击知识库，覆盖主流 Web 攻击类型和 MCP 场景特有的 Prompt Injection
- 零额外配置：用户 `docker-compose up` 即可使用 RAG，不需要填 embedding API key
- 镜像增量控制在 200MB 以内
- RAG 检索延迟控制在 10ms 以内，不显著影响代理总延迟

**Non-Goals:**

- 不做 GraphRAG / 知识图谱推理（数据量不需要，复杂度不值得）
- 不做远程 embedding API 模式（简化用户配置，避免厂商兼容性问题）
- 不做知识库在线更新（预构建打包进镜像，更新通过重新构建镜像完成）
- 不改动 WAF1 的任何逻辑
- 不改动 `call_llm()` 的多 Provider 支持逻辑
- 不做生产级部署优化（这是作品赛项目）

## Decisions

### D1: Embedding 方案 — 本地 ONNX 模型，不走 API

**选择：** 容器内置 ONNX 格式的 `all-MiniLM-L6-v2` 模型（~22MB）

**备选方案：**
- 方案 A：调用厂商 Embedding API（OpenAI `text-embedding-3-small`、Qwen `text-embedding-v3` 等）
- 方案 B：本地 PyTorch + `sentence-transformers` + `bge-large-zh`
- 方案 C（选定）：本地 ONNX Runtime + `all-MiniLM-L6-v2`

**理由：**
- 方案 A 需要用户额外配置 embedding key，且部分厂商（Anthropic、DeepSeek）没有 embedding API，体验不一致
- 方案 B 引入 PyTorch 依赖（~800MB），镜像膨胀到 1.2GB
- 方案 C 用 ONNX Runtime（~50MB）替代 PyTorch，模型仅 22MB，CPU 推理 < 5ms，镜像增量可控。`all-MiniLM-L6-v2` 在短文本语义相似度任务上表现足够，payload 文本通常很短（几个字符到一行）

### D2: 向量存储 — ChromaDB 进程内模式

**选择：** ChromaDB in-process，持久化到容器内文件目录

**备选方案：**
- 方案 A：独立 ChromaDB 服务（Client/Server 模式）
- 方案 B（选定）：ChromaDB 进程内模式
- 方案 C：纯 numpy 余弦相似度

**理由：**
- 知识库规模 ~5000-6000 条，不需要独立服务
- 进程内模式零网络开销，检索延迟 < 2ms
- ChromaDB 比纯 numpy 多了持久化、metadata 过滤、索引管理，开发体验更好
- 不需要在 docker-compose.yml 中新增服务

### D3: 知识库数据结构

**选择：** 每条记录为一个 JSON 对象，包含 payload 文本 + 结构化 metadata

```json
{
  "text": "' OR 1=1 --",
  "category": "sql_injection",
  "metadata": {
    "cwe": "CWE-89",
    "capec": "CAPEC-66",
    "owasp": "A03:2021",
    "severity": "high",
    "description": "经典布尔型 SQL 注入，绕过 WHERE 条件",
    "source": "PayloadsAllTheThings"
  }
}
```

**理由：**
- `text` 字段用于 embedding 和相似度检索
- `metadata` 字段用于检索后的过滤和 LLM prompt 上下文组装
- CWE/CAPEC/OWASP 映射链参考 CyRAG 的知识组织结构，让 LLM 输出带归因信息
- `source` 字段标注数据来源，便于知识库维护和溯源

### D4: 知识库数据源与优先级

**选择：** 分两期构建

| 优先级 | 数据源 | 条目数 | 获取方式 |
|--------|--------|--------|----------|
| P0 | PayloadsAllTheThings | ~4000 | git clone，按目录分类 |
| P0 | OWASP CRS 规则 | ~800 | git clone coreruleset，解析 .conf |
| P0 | OWASP Prompt Injection cheat sheets | ~300 | GitHub 仓库 |
| P1 | CWE Top 25 + Web 相关 | ~50 | MITRE 官网 XML/JSON |
| P1 | CAPEC Web 相关 | ~200 | MITRE 官网 XML |

**理由：**
- P0 数据源直接提供攻击 payload，和 WAF 检测场景完美匹配，且获取成本低
- Prompt Injection 数据对 MCP 场景特别重要，是项目差异化的关键
- P1 的 CWE/CAPEC 提供分类体系和归因标签，增强 LLM 输出质量
- CVE 原始数据（NVD）量太大、噪音多，投入产出比低，不纳入

### D5: 检索策略

**选择：** top-5 相似度检索 + metadata category 过滤 + 相似度阈值

```
检索流程:
1. 将请求文本 embedding 为向量
2. 在 ChromaDB 中检索 top-5 最相似记录
3. 过滤掉相似度低于 0.5 的结果（避免不相关结果干扰 LLM）
4. 将剩余结果格式化为上下文段，塞入 prompt
```

**理由：**
- K=5 在信息量和 prompt 长度之间取平衡，payload 文本短，5 条不会占太多 token
- 相似度阈值 0.5 是初始值，可根据实际测试调整
- 不做 category 预过滤（让向量相似度自然筛选），避免漏掉跨类别的攻击变体

### D6: Prompt 增强方式

**选择：** 在现有 prompt 模板中新增 `{retrieved_context}` 段落

```
## 相似攻击参考 (知识库检索)
{retrieved_context}

格式:
1. [sql_injection] ' OR 1=1 -- (CWE-89, CAPEC-66, severity: high)
   说明: 经典布尔型 SQL 注入，绕过 WHERE 条件
2. [sql_injection] 1' UNION SELECT null,null -- (CWE-89, severity: high)
   说明: 联合查询注入，探测列数
...
如果以上参考为空，则仅凭自身知识判断。
```

**理由：**
- 参考 Springer 论文的 Self-Ranking 思路：检索结果按相似度排序呈现，提示 LLM 优先参考前几条
- 保留"如果参考为空"的 fallback，确保 RAG 检索无结果时不影响原有判断能力
- 不改变 LLM 输出格式（仍然是 `PASS` 或 `BLOCK|category|reason`），下游解析逻辑不变

### D7: 知识库构建与打包流程

**选择：** 离线构建，预打包进 Docker 镜像

```
开发时:
  build_kb.py → 读取数据源 → 清洗/结构化 → embedding → 写入 ChromaDB
                                                          ↓
                                                   waf2/rag/data/chroma_db/

Docker 构建时:
  Dockerfile COPY waf2/rag/data/ → 镜像内

用户运行时:
  容器启动 → 加载 /app/rag/data/chroma_db/ → 就绪
```

**理由：**
- 用户不需要自己构建知识库，开箱即用
- 知识库更新通过重新运行 `build_kb.py` + 重新构建镜像完成
- 构建脚本参考 CVE-KGRAG 的数据处理流程

### D8: RAG 在检测管线中的位置

**选择：** 插入在 `static_rule_check()` 之后、`call_llm()` 之前

```
现有:  请求 → static_rule_check() → analyze_request() → call_llm() → 判断
改后:  请求 → static_rule_check() → rag_retrieve() → analyze_request() → call_llm() → 判断
                                      ↑ 新增                ↑ prompt 模板变更
```

**理由：**
- 静态规则命中的请求已经被拦截，不需要浪费 RAG 检索
- RAG 检索结果作为 `analyze_request()` 的输入参数，由它组装进 prompt
- `call_llm()` 完全不改，只是收到的 prompt 内容更丰富了

## Risks / Trade-offs

**[镜像体积增加 ~170MB]** → 从 ~140MB 到 ~310MB。在 Docker 生态中仍属正常范围（WordPress 镜像 ~620MB）。对作品赛评委拉取镜像的体验影响可忽略。

**[Embedding 模型质量]** → `all-MiniLM-L6-v2` 是英文为主的模型，对中文 payload 的 embedding 质量可能不如 `bge-small-zh`。→ 缓解：攻击 payload 大部分是英文/代码片段（SQL、shell 命令、HTML 标签），中文 prompt injection 是少数场景。如果测试发现中文效果差，可替换为 `paraphrase-multilingual-MiniLM-L12-v2`（~120MB，多语言支持），镜像增量仍可控。

**[检索结果误导 LLM]** → 如果检索出不相关的结果，可能让 LLM 产生误判。→ 缓解：设置相似度阈值（0.5），低于阈值的结果不塞入 prompt；prompt 中明确提示"如果参考为空则凭自身知识判断"。

**[知识库静态，不能在线更新]** → 新攻击手法出现后需要重新构建镜像。→ 缓解：作品赛场景下不需要实时更新；`build_kb.py` 脚本可快速重建。

**[ChromaDB 内存占用]** → ~5000 条记录的向量索引约占 50MB 内存。→ 缓解：WAF2 容器本身内存占用很低（~80MB），加上 50MB 仍在合理范围。

## Open Questions

- `all-MiniLM-L6-v2` vs `paraphrase-multilingual-MiniLM-L12-v2`：需要实际测试中文 prompt injection payload 的检索效果再最终确定
- 相似度阈值 0.5 是否合适：需要用测试集验证，可能需要调整
- 响应分析（`analyze_response()`）是否也需要 RAG 增强：当前设计两个 prompt 都加，但响应分析检测的是数据泄露，知识库中的攻击 payload 对它帮助可能有限，可能只需要增强请求分析
