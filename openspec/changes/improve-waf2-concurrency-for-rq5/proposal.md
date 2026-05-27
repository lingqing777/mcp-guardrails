## Why

论文 RQ5（5.6 节）要评测 WAF2 在 CSIC-HTTP 大规模数据面下的实时性与资源开销，并验证三个观察重点：(a) 系统在普通硬件下持续可运行；(b) 大多数请求在本地快速路径完成；(c) 模型路径只承担少量复杂样本，未成主吞吐瓶颈。

但当前 `waf2/waf2_proxy.py` 的并发模型会使表 5.8 关键数字失真：FastAPI async handler 内调用同步 `requests.post()` 做 LLM（`waf2_proxy.py:759-823`）、同步调 ChromaDB（`rag/knowledge_base.py:135`）与 ONNX embedder（`rag/engine.py:104`），任一慢调用都会阻塞 event loop，使同期到达的 stage0/local 快速路径请求被一起拖慢；同时 `LLMCache` 在并发 miss 时会重复打 LLM 导致缓存命中率指标被低估；`stats` 字典只有总计、没有按路由路径分桶，无法直接读出 RQ5 的「路由比例」与「分路径延迟分布」。不修正这些会让论文的 P95/缓存命中率/路由比例数字反映事件循环阻塞，而非 WAF2「本地优先、模型只承担少量复杂样本」的设计本意。

## What Changes

- **async LLM 客户端**：把 `call_llm` 改为 `async def`，`requests.post` → `httpx.AsyncClient` 单例 + 连接池；所有调用点改 `await`
- **Chroma/ONNX 异步化**：用 `asyncio.to_thread()` 包装同步检索与 embedding 调用，不改底层 API
- **LLMCache 单飞（single-flight）**：用 `asyncio.Future` 合并同 key 并发 miss，保证同 payload 并发请求只打一次 LLM
- **分路径延迟直方图**：新增 per-route latency tracker（`stage0` / `local_only` / `rag` / `llm` 四桶），基于 `collections.deque` + numpy percentile；`/waf2/stats` 增加 `per_path_latency` 字段供姊妹提案 `add-waf2-rq5-perf-eval-harness` 消费
- **LLM 并发上限（保险）**：新增 `LLM_CONCURRENCY` 配置（默认 8），用 `asyncio.Semaphore` 包住 `call_llm` 防压测下游雪崩
- **不**多 worker（保持 stats 单进程聚合）；**不**改 `waf2_proxy_lite.py`（生产入口确认为 `waf2_proxy.py`，Dockerfile:26）；**不**做过载降级、**不**给 stats dict 加锁（asyncio 单线程下 `dict[k]+=1` 已原子）

## Capabilities

### New Capabilities

无。本提案修改既有 WAF2 能力的实现与运行时契约，未引入新的安全能力。

### Modified Capabilities

- `waf2`：新增/修改的 spec-level 行为
  - 数据面 LLM 调用、向量检索、embedder 调用 MUST 不阻塞 FastAPI event loop
  - `LLMCache` MUST 对同 key 的并发 miss 做 single-flight 合并
  - `/waf2/stats` MUST 暴露分路径延迟分布（P50/P95/P99）与路由计数字段
  - `call_llm` MUST 受可配置的并发上限保护（`LLM_CONCURRENCY`，默认 8）

## Impact

- **影响范围**（外科手术，单层）：
  - `waf2/waf2_proxy.py`（主改造：`call_llm` async 化、`LLMCache` single-flight、stats 分桶）
  - `waf2/rag/engine.py`、`waf2/rag/knowledge_base.py`（`asyncio.to_thread()` 包装调用点）
  - `waf2/tests/`（新增异步/并发单元测试 + 烟雾测试）
  - `config/guardrails-config.json`（新增 `LLM_CONCURRENCY` 默认配置）
- **不影响**：
  - WAF1 / MCP Hub / Dashboard / 路由注册顺序 / 认证边界（server.js 等 Node 侧零改动）
  - `waf2/waf2_proxy_lite.py`（评测分支保持原样）
  - Docker 编排与端口（沿用 8081，Dockerfile / docker-compose.yml 不变）
- **依赖与版本**：
  - `httpx` 已在依赖中（用于 upstream 代理），直接复用其异步客户端能力
  - `numpy` 用于 percentile，已是 RAG 依赖
- **后续提案**：`add-waf2-rq5-perf-eval-harness` 将消费 `/waf2/stats` 新增的 `per_path_latency` 字段生成表 5.8
- **风险**：
  - async 化触碰生产入口的核心调用链，需要充分单测与并发烟雾测试覆盖
  - 现有调用点广泛（`call_llm` 在 stage0 / local / rag / agent 多处被调），改 await 需扫描全文件
