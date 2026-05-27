## Context

WAF2 (`waf2/waf2_proxy.py`) 是论文 RQ5 的被测对象,部署在 Docker 容器中 (`Dockerfile:26`),通过 FastAPI + httpx 反向代理架构监听 8081。当前实现一个反模式很显眼:`async def proxy()` 主 handler 内部串联调用同步阻塞代码 —— `requests.post()` 打 LLM (30s timeout)、ChromaDB `query()` 与 ONNX `encode()` 都同步执行 —— 这些调用会霸占 uvicorn 事件循环。

后果对 RQ5 表 5.8 的影响是致命的:WAF2 的设计卖点是**绝大多数请求在 stage0 正则 / local_attack_score 本地路径完成,不到 LLM**,因此 P95 期望落在数毫秒级;但当下任一并发场景下,只要有一个慢 LLM 请求在跑,事件循环就被卡住,同期 stage0 请求的延迟会被拖到秒级,P95 反映的是事件循环阻塞而非系统设计。再加上 `LLMCache` 并发 miss 不合并、`stats` 只有总计无分桶,「缓存命中率」「路由比例」「分路径延迟」三个论文指标都无法干净读出。

约束:
- 本地部署、面向裁判演示,**不**追求生产级横向扩展
- 单进程内做改造,以保证 `stats` 字典作为权威路由计数源不分裂
- 既有评测分支 `waf2_proxy_lite.py` 与 Docker / docker-compose 编排保持原样
- 改造必须保留现有 `/waf2/stats` / `/waf2/config` 等 API 的响应结构(只新增字段,不删除已有字段)

## Goals / Non-Goals

**Goals:**
- 数据面 LLM 调用、向量检索、embedder 调用 **不**阻塞 FastAPI event loop
- `LLMCache` 对同 key 的并发 miss 做 single-flight 合并,使缓存命中率指标可信
- `/waf2/stats` 暴露**分路径** (stage0 / local_only / rag / llm) 的延迟分布 (P50/P95/P99) 与请求计数
- `call_llm` 受可配置并发上限保护,压测下不让下游 LLM 雪崩
- 现有单元测试与烟雾测试套件全部保持绿;新增并发烟雾测试证明「stage0 路径 P95 不被同期 LLM 请求拖累」
- 改动集中在 `waf2/`,**零**触碰 mcp-hub / server.js 路由顺序 / 认证边界 / Dashboard / WAF1

**Non-Goals:**
- 多 worker 横向扩展 (会让 stats 跨进程分裂,破坏 RQ5 路由比例指标)
- 改造 `waf2_proxy_lite.py` (评测分支保持原样)
- 过载降级 / 优雅 503 (RQ5 测稳态,不测过载)
- 对 stats dict 加 threading/asyncio Lock (asyncio 单线程下 `dict[k]+=1` 已原子)
- Dashboard UI 改动 (本提案不暴露新 UI;`per_path_latency` 字段是给姊妹提案的压测 driver / 报告脚本消费的,不进 Dashboard)
- 修改 LLM Provider 协议契约 (call_llm 行为、prompt、解析格式不变)

## Decisions

### D1. async LLM 客户端 — 用 `httpx.AsyncClient` 单例

`call_llm()` 改为 `async def`,内部用模块级 `httpx.AsyncClient` 单例。原因:
- 项目 upstream 代理已用 `httpx`(`waf2_proxy.py:2674`),无需引入新依赖
- 单例 + 连接池让多次 LLM 调用复用 TCP/TLS,降低短连接开销
- 现存 `LLM_TIMEOUT_SECONDS` 配置 (`waf2_proxy.py:142`) 平移为 httpx 的 `timeout=` 参数

**替代方案**:
- `aiohttp` — 项目未使用,引入新依赖且与 upstream 风格不一致 → 弃
- 保留 sync requests + `asyncio.to_thread()` 包装 — 可行但每次调用都借 threadpool 线程,无连接池复用 → 弃

**调用点扫描**:`call_llm` 在 stage0 / local-only / rag / agent ReAct 多处被调用,改 async 后必须扫全文件把所有调用点改为 `await`。tasks.md 会把这一步拆成独立 task。

### D2. Chroma / ONNX → `asyncio.to_thread()`

`rag/engine.py:104` 的 retrieve 链路与 `rag/knowledge_base.py:135` 的 Chroma `query()` 用 `asyncio.to_thread()` 包装。原因:
- ChromaDB Python 客户端不支持 async,封装层不去触碰
- ONNX 推理是 CPU-bound,从事件循环搬到默认 threadpool 不会更慢,但能解放 loop 让其它请求推进
- `asyncio.to_thread()` 是 Python 3.9+ 标准库,无新依赖

**替代方案**:
- 自建 `concurrent.futures.ProcessPoolExecutor` — 进程间 IPC 序列化 numpy/embedding 开销不值得 → 弃
- 改 Chroma async-mode (httpx-chroma server) — 架构变化太大,违背「外科手术」约束 → 弃

### D3. LLMCache — single-flight 改造

`LLMCache.get()` 改为 `async`,内部维护 `Dict[str, asyncio.Future]`(in-flight 表)。新流程:
1. cache 命中 → 直接返回
2. cache miss 且 in-flight 表有同 key → `await` 复用该 Future
3. cache miss 且 in-flight 无 key → 创建 Future、调 LLM、`set_result`、写入 cache、清理 in-flight 表

原因:
- 论文表 5.8 要报「缓存命中率」,并发 miss 风暴会让命中率被低估、且会无意义放大 LLM 请求
- single-flight 是无锁(asyncio 单线程)实现,几十行代码搞定

**替代方案**:
- 用 `asyncio.Lock` 串行所有 cache 访问 — 把不同 key 的请求也串行,损失并发 → 弃
- 不做合并,接受缓存命中率失真 — 直接违背 RQ5 指标要求 → 弃

**LRU 行为**:保留现有 `max_size=500` 与 5min TTL,不改变淘汰策略;single-flight 表与 LRU 表分离。

### D4. 分路径延迟直方图 — 滑动窗口 deque + numpy percentile

新增 `PathLatencyTracker` 类,持有 4 个 `collections.deque(maxlen=N)`(默认 N=1024,可配置),分别记录 stage0 / local_only / rag / llm 四条路径的最近 N 次请求延迟;暴露 `snapshot()` → `{path: {p50, p95, p99, count}}`。在 handler 的 stage 边界处 push 样本。

原因:
- 论文表 5.8 的 P50/P95/P99 主要靠压测客户端 driver 出数据,但**分路径**的数据 driver 拿不到 (它不知道 WAF2 内部走了哪条路径) → 必须服务端埋点
- deque maxlen 自动淘汰旧样本,内存可控
- 不引入 prometheus_client 等依赖(单进程,RQ5 表格够用,Dashboard 不暴露)

**替代方案**:
- `prometheus_client.Histogram` — 标准但多一个依赖,且 RQ5 不上 Prometheus → 弃
- 全量保留延迟列表 — 长时间压测内存爆 → 弃

**stats 字段扩展**:`/waf2/stats` 响应新增 `per_path_latency` 字段(结构如上),其余字段不动。Dashboard 5 秒刷新只读已有字段,不破坏。

### D5. LLM 并发上限 — `asyncio.Semaphore`

新增 `LLM_CONCURRENCY` 配置(默认 8),用 `asyncio.Semaphore(LLM_CONCURRENCY)` 包住 `call_llm` 真实 HTTP 调用(放在 single-flight 创建 Future 之后,实际 await httpx.AsyncClient.post 之前)。原因:
- 压测时上游 LLM 可能限流;不限并发会触发上游 5xx 雪崩
- 8 是经验值,足够让 P95 在 LLM 路径上正常分布,又不至于把上游打挂
- 排队语义符合 asyncio 默认 FIFO,无饥饿

**Semaphore vs single-flight 顺序**:
- single-flight 在 Semaphore 之前 — 完全相同 payload 的并发请求合并成 1 次实际调用,只消耗 1 个信号量
- 不同 payload 的并发请求各自需要 1 个信号量

### D6. stats dict — 不加锁

asyncio 单线程模型下,`stats[k] += 1`、`stats[k1] = stats[k2]` 等单语句都是原子(GIL 在字节码层面保证,且不跨 `await`)。本次改造**审计**所有 stats 修改点,确保没有 `read → await → write` 模式,即可不加锁。如果发现跨 `await` 的复合操作,局部用 `asyncio.Lock`,不引入全局锁。

**替代方案**:多 worker → 上 Redis/Prometheus 共享计数 → 与「Non-Goals」冲突 → 弃。

### D7. 配置位置

`LLM_CONCURRENCY` 与 `PATH_LATENCY_WINDOW` 两个新配置项:
- 写入 `config/guardrails-config.json` 的 `waf2` 段,与既有 `LLM_TIMEOUT_SECONDS` 同级
- 在 `waf2_proxy.py` 启动期读入,运行期可通过 `/waf2/config` POST 热更新(沿用现有热更新通道)
- Semaphore 实例创建后,运行期改并发上限的语义是「下次创建时生效」,本次提案不实现热改 Semaphore(复杂且 RQ5 不需要)

## Risks / Trade-offs

- **[风险] async 化触碰核心调用链,可能遗漏调用点导致协程未 await** → 修改后用 `grep -n 'call_llm\|_do_rag_retrieve' waf2/` 扫一遍,所有调用点 + 测试覆盖;CI 跑 `python -m compileall` 加 `pytest -W error::RuntimeWarning` 捕捉 unawaited coroutine 警告
- **[风险] httpx.AsyncClient 单例在测试中难以 patch** → 改造时把单例放在模块级工厂函数后,测试用 monkeypatch 替换;新增的并发烟雾测试用 respx 或 httpx MockTransport mock LLM 响应
- **[风险] `asyncio.to_thread()` 默认 threadpool 大小默认 `min(32, cpu+4)`,压测时可能不够** → 在启动期通过 `loop.set_default_executor(ThreadPoolExecutor(max_workers=N))` 调整,N 由新配置 `THREADPOOL_MAX_WORKERS`(默认 32)控制
- **[风险] LLMCache single-flight 时 Future 抛异常,等待方都会拿到同一异常** → 这是期望行为(避免重复打 LLM 失败),但 in-flight 表 cleanup 必须在 finally 里执行,防止泄漏
- **[风险] PathLatencyTracker 在测试中累计干扰** → tracker 实例可重置;测试夹具初始化时调 `reset()`
- **[Trade-off] 单进程上限 ≈ 1 CPU core** → 对 WAF2(80-95% 时间花在 LLM 等待上)足够;若未来要突破,需另起多 worker 提案并把 stats 外置
- **[Trade-off] 切口 5 (Semaphore) 在 RQ5 稳态测试下基本不触发** → 仍保留,作为压测保险;默认值 8 不会过于限制
- **[未决问题] threadpool 大小默认值** → 32 是合理默认,但首次跑 RQ5 时可能需要根据 CPU 核数调整 → 列入压测 driver 的 sweep 参数,姊妹提案再确认

## Migration Plan

本提案改动集中在 `waf2/` 容器内,无数据迁移、无 API 破坏:
1. 改造按 tasks.md 顺序合入,每个切口独立可回滚
2. Docker 镜像重新构建(`docker compose build waf2`),无 Dockerfile 改动
3. 配置兼容:新配置项缺失时使用代码内默认值,无破坏性变更
4. 回滚策略:`git revert` 单个 task 提交即可,无外部依赖
