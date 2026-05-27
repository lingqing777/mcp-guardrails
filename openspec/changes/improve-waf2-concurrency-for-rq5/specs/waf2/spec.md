## ADDED Requirements

### Requirement: 数据面调用不阻塞事件循环
WAF2 数据面 (`waf2/waf2_proxy.py`) 在 FastAPI async handler 中调用 LLM、向量数据库 (ChromaDB) 与 embedder (ONNX) 时,MUST 不阻塞 uvicorn 事件循环;一个慢的下游调用 MUST NOT 阻塞同一事件循环上其它已在飞的请求处理。LLM HTTP 调用 MUST 通过异步 HTTP 客户端发起(基于既有 `httpx` 依赖);同步底层组件 (ChromaDB Python 客户端、ONNX 推理) MUST 通过 `asyncio.to_thread()` 或等价线程池机制隔离到工作线程,使主事件循环保持可调度。

影响层:WAF2 (Docker 容器,端口 8081),不触碰 MCP Hub / WAF1 / Dashboard。

#### Scenario: 长 LLM 调用不应拖慢同期 stage0 请求
- **WHEN** 一个请求路由到 LLM 路径且 LLM 响应耗时 1 秒,同期到达 100 个走 stage0 正则快速路径的请求
- **THEN** 100 个 stage0 请求 P95 延迟 MUST 保持在 50ms 以内(不被 LLM 等待拖慢),系统 MUST 在 LLM 返回前持续接受并响应 stage0 请求

#### Scenario: ChromaDB 查询不应阻塞事件循环
- **WHEN** 一个请求触发 RAG 路径,ChromaDB query 耗时 30ms
- **THEN** 同期到达的不走 RAG 的请求 MUST 在 query 期间继续被 handler 接受与处理,事件循环 MUST 不被阻塞超过单次调度让出时间

#### Scenario: ONNX embedder 不应阻塞事件循环
- **WHEN** 一个请求需要计算 query embedding,ONNX 推理耗时 80ms
- **THEN** 同期到达的其他请求 MUST 不被该推理阻塞,embedder 调用 MUST 在工作线程而非事件循环线程上执行

### Requirement: LLMCache 并发请求合并 (single-flight)
WAF2 的 LLM 结果缓存 (`LLMCache`,`waf2/waf2_proxy.py:119-142`) MUST 对同一 cache key 的并发 miss 做 single-flight 合并:当多个协程同时未命中同一 key 时,只有第一个协程实际发起 LLM 调用,后续协程 MUST 等待该调用结果共享同一返回值,而 NOT 各自重复打 LLM。合并机制 MUST 使用 `asyncio.Future` 等单进程 asyncio 原语实现,无需引入跨进程同步设施。

当受合并的 LLM 调用抛出异常时,所有等待协程 MUST 收到同一异常;in-flight 表项 MUST 在调用完成(成功或失败)后被清理,以避免泄漏。

影响层:WAF2 (单进程内)。

#### Scenario: 同 payload 并发请求合并为单次 LLM 调用
- **WHEN** 20 个并发请求具有完全相同的 LLM cache key 且缓存当前为 miss
- **THEN** 实际发起的 LLM HTTP 调用次数 MUST 等于 1,20 个请求 MUST 全部拿到相同的判定结果

#### Scenario: 不同 payload 并发请求互不影响
- **WHEN** 10 个并发请求具有 10 个不同的 cache key
- **THEN** 实际发起的 LLM 调用次数 MUST 等于 10,无请求被另一 key 的调用阻塞

#### Scenario: LLM 失败时等待方共享异常
- **WHEN** 5 个并发请求合并到同一 in-flight 调用,该调用以异常终止
- **THEN** 5 个请求 MUST 全部收到等价异常或失败标记,且 in-flight 表中对应 key MUST 被清理(后续相同 key 请求 MUST 触发新调用)

### Requirement: 分路径延迟分布暴露
WAF2 MUST 在 `/waf2/stats` 与 `/waf2/dashboard` 响应中新增 `per_path_latency` 字段,按四条路由路径(`stage0`、`local_only`、`rag`、`llm`)分别报告 P50 / P95 / P99 延迟(单位毫秒)与请求计数(`count`)。延迟样本 MUST 通过滑动窗口(默认 1024 样本,可通过 `PATH_LATENCY_WINDOW` 配置)维护,内存占用 MUST 有界。

字段结构 MUST 形如:`{"per_path_latency": {"stage0": {"p50": <num>, "p95": <num>, "p99": <num>, "count": <int>}, "local_only": {...}, "rag": {...}, "llm": {...}}}`。当某路径无样本时,该路径字段 MUST 仍出现,数值字段 MUST 为 `null` 或 `0`,`count` MUST 为 `0`。`POST /waf2/reset` MUST 同时重置 `per_path_latency` 全部窗口。

现有 `/waf2/stats` 与 `/waf2/dashboard` 已有字段 MUST 保持原结构与含义不变(纯字段新增,无破坏)。

影响层:WAF2 API。Dashboard 5 秒刷新只读已有字段,不消费新字段,Dashboard 不需改动。

#### Scenario: 各路径请求按窗口统计
- **WHEN** 客户端依次发送 100 个 stage0 命中、50 个 local_only 路由、20 个 rag、5 个 llm 请求,随后查询 `GET /waf2/stats`
- **THEN** 响应 MUST 包含 `per_path_latency` 字段,`stage0.count` MUST = 100,`local_only.count` MUST = 50,`rag.count` MUST = 20,`llm.count` MUST = 5,各路径 p50/p95/p99 MUST 为正数毫秒值

#### Scenario: 窗口溢出时丢弃最旧样本
- **WHEN** `PATH_LATENCY_WINDOW=100` 且向 stage0 路径连续推 200 个延迟样本
- **THEN** `per_path_latency.stage0.count` MUST = 100(等于窗口大小,体现最近 100 个样本),p50/p95/p99 MUST 基于最近 100 个样本计算

#### Scenario: 重置清空所有路径窗口
- **WHEN** 各路径有累积样本,客户端调用 `POST /waf2/reset`
- **THEN** `GET /waf2/stats` 返回的 `per_path_latency` 中四条路径 `count` MUST 均为 0

### Requirement: LLM 调用并发上限可配置
WAF2 MUST 通过 `asyncio.Semaphore` 限制同时在飞的实际 LLM HTTP 调用数,上限由配置 `LLM_CONCURRENCY` 控制(默认 8)。当 in-flight LLM 调用数已达上限时,新调用 MUST 进入 FIFO 等待队列,等已有调用释放后再发起;等待队列 MUST 无超时强制中断(超时仍由现有 `LLM_TIMEOUT_SECONDS` 在实际 HTTP 层兜底)。

并发上限 Semaphore MUST 包裹「实际发起 HTTP 调用」的代码块,且 MUST 位于 LLMCache single-flight 合并之后 —— 即同 key 的并发请求先在 single-flight 处合并,只有合并后的「领跑者」消费一个信号量。

`LLM_CONCURRENCY` MUST 在容器启动期读入;运行期通过 `POST /waf2/config` 修改该字段时,生效语义为「下次容器启动生效」(本提案不要求热改 Semaphore 容量)。

影响层:WAF2,配置项位于 `config/guardrails-config.json` 的 `waf2` 段。

#### Scenario: 超过上限的请求进入排队
- **WHEN** `LLM_CONCURRENCY=2`,3 个不同 cache key 的请求同时触达 LLM 路径
- **THEN** 同一时刻实际并发的 LLM HTTP 调用数 MUST ≤ 2,第 3 个请求 MUST 等待前两个之一释放信号量后再发起,且最终 3 个请求都 MUST 完成

#### Scenario: single-flight 合并不消耗多个信号量
- **WHEN** `LLM_CONCURRENCY=1` 且 5 个并发请求具有相同 cache key
- **THEN** 实际发起的 LLM 调用数 MUST = 1,信号量 MUST 只被占用 1 次,5 个请求 MUST 共享结果且全部完成

### Requirement: 现有 WAF2 API 与拦截契约保持稳定
本次改造 MUST NOT 破坏现存 WAF2 行为契约:
- 拦截响应仍 MUST 返回 HTTP 403,响应体格式 MUST 保持 `{ error: "WAF2 拦截", direction, category, severity, reason, owasp, mitre }`(对应既有 WAF2-30 / WAF2-31)
- `call_llm` 解析 LLM 输出仍 MUST 区分 `PASS`、`BLOCK|<category>|<reason>`、`ERROR` 三态(对应既有 WAF2-11、WAF2-23)
- LLM Provider 三种格式(`openai` / `anthropic` / `gemini`)的请求构造逻辑 MUST 保持不变(对应既有 WAF2-20)
- `LLMCache` 容量 500、TTL 5 分钟、MD5 key 不变(对应既有 WAF2-25 / WAF2-26)
- `/waf2/config`、`/waf2/cache/clear`、`/waf2/stats`、`/waf2/dashboard`、`/waf2/detections`、`/waf2/reset`、`/waf2/health`、`/<path:path>` 端点路径与既有响应字段 MUST 保持(对应既有 WAF2-40 ~ WAF2-48,仅 stats 与 dashboard 允许字段新增)
- `waf2_proxy_lite.py` 评测分支 MUST NOT 被本次改造修改

#### Scenario: 拦截响应格式不变
- **WHEN** 一个 SQL 注入请求被 WAF2 LLM 判定为 BLOCK
- **THEN** 响应 MUST 返回 HTTP 403,body MUST 满足现有 `{ error, direction, category, severity, reason, owasp, mitre }` 结构,字段名称与值类型 MUST 与改造前一致

#### Scenario: 既有 stats 字段保持可用
- **WHEN** Dashboard 5 秒刷新调用 `GET /waf2/dashboard`
- **THEN** 响应 MUST 仍包含改造前已有的所有字段(总请求数、通过数、拦截数、缓存命中、LLM 调用、平均延迟、`llm_errors` 等),Dashboard 当前实现 MUST 无需改动即可正常渲染
