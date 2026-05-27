## 1. 准备与基线确认

- [x] 1.1 在 `waf2/` 启动现有 `pytest waf2/tests/` 验证基线全绿,记录基线测试列表与覆盖率,作为回归基准
- [x] 1.2 通过 `grep -nE "call_llm|_do_rag_retrieve|retrieve\(" waf2/` 全量扫描调用点,生成「调用点清单」附在本文档末尾(实现时核对)
- [x] 1.3 在 `config/guardrails-config.json` 的 `waf2` 段新增默认配置:`LLM_CONCURRENCY=8`、`PATH_LATENCY_WINDOW=1024`、`THREADPOOL_MAX_WORKERS=32`(代码加载时若缺省则用内置默认,不破坏既有配置文件)

## 2. 切口 1 — async LLM 客户端 (D1)

涉及:`waf2/waf2_proxy.py:759-823` (`call_llm`)、全文件所有调用点

- [x] 2.1 新增模块级 `httpx.AsyncClient` 单例工厂(便于测试 monkeypatch),timeout 沿用 `config.llm_timeout_seconds`,关闭由 FastAPI shutdown 钩子触发
- [x] 2.2 把 `call_llm()` 改为 `async def`,内部 `requests.post` → `await httpx_client.post`;保留三种 Provider(`openai`/`anthropic`/`gemini`)的请求构造逻辑与解析格式不变(对应既有 WAF2-20)
- [x] 2.3 按 1.2 调用点清单,逐一把 sync 调用改为 `await call_llm(...)`(stage0 / local-only / rag / agent ReAct 多处)
- [x] 2.4 新增单元测试 `waf2/tests/test_call_llm_async.py`:用 `respx` 或 `httpx.MockTransport` mock LLM 响应,覆盖 PASS / BLOCK / ERROR 三态、三种 Provider 格式
- [x] 2.5 在测试 fixtures 中确认 `RuntimeWarning: coroutine was never awaited` 在 `pytest -W error::RuntimeWarning` 下不出现(防止漏改 await)

## 3. 切口 2 — Chroma / ONNX 异步包装 (D2)

涉及:`waf2/rag/engine.py:104`、`waf2/rag/knowledge_base.py:135`

- [x] 3.1 在 `rag/engine.py` 新增 `async def aretrieve(...)`,内部 `await asyncio.to_thread(self.retrieve, ...)`;保留同步 `retrieve()` 不删除(供非异步调用方)
- [x] 3.2 在 `rag/knowledge_base.py` 新增对 Chroma `query()` 的异步包装(若 retrieve 内部直接调 query 则上层包一次即可,避免多线程嵌套)
- [x] 3.3 在 `waf2_proxy.py` 启动期(`@app.on_event("startup")` 或等价)通过 `loop.set_default_executor(ThreadPoolExecutor(max_workers=config.threadpool_max_workers))` 设置默认线程池大小
- [x] 3.4 把 `waf2_proxy.py` 中 `_do_rag_retrieve` 等 RAG 调用点改为调用 `aretrieve` 并 `await`
- [x] 3.5 新增单元测试 `waf2/tests/test_rag_async.py`:验证 `aretrieve` 返回与同步 `retrieve` 等价结果,验证调用期间事件循环不被阻塞(用 `asyncio.gather(aretrieve(), sleep_zero_loop_check())` 验证)

## 4. 切口 3 — LLMCache single-flight (D3)

涉及:`waf2/waf2_proxy.py:119-142` (`LLMCache`)

- [x] 4.1 把 `LLMCache.get(key)` 改为 `async def`,新增 `self._inflight: Dict[str, asyncio.Future]` 字段
- [x] 4.2 实现 single-flight 流程:命中直接返回;miss 且 in-flight 有同 key 则 `await` 该 Future;miss 且无 in-flight 则创建 Future、调 LLM、`set_result`、写入 cache、`finally` 清理 in-flight 表
- [x] 4.3 保留现有 `max_size=500` 与 5min TTL LRU 行为不变(对应既有 WAF2-25 / WAF2-26)
- [x] 4.4 异常路径:被合并的 LLM 调用抛异常时,所有等待方 `await` 都拿到同一异常;in-flight 表项在 `finally` 中清理
- [x] 4.5 新增单元测试 `waf2/tests/test_llm_cache_single_flight.py`:
  - 同 key 20 并发请求 → 实际 LLM 调用次数 == 1(对应 spec scenario)
  - 不同 key 10 并发请求 → 实际 LLM 调用次数 == 10
  - 合并请求抛异常 → 所有等待方收到同一异常,后续相同 key 请求触发新调用(in-flight 已清理)

## 5. 切口 4 — 分路径延迟直方图 (D4)

涉及:`waf2/waf2_proxy.py` stats 区与 stage 边界

- [x] 5.1 新增 `PathLatencyTracker` 类(`waf2/waf2_proxy.py` 内或新建 `waf2/path_latency.py`),持有 `Dict[str, collections.deque]`,4 个路径:`stage0` / `local_only` / `rag` / `llm`;`maxlen=config.path_latency_window`
- [x] 5.2 实现 `record(path, latency_ms)`、`snapshot()` → 每路径 `{p50, p95, p99, count}`(用 `numpy.percentile`),`reset()` 清空全部窗口
- [x] 5.3 在 handler 各 stage 边界埋点:stage0 路径在返回前 record;local_only 在返回前 record;rag 路径在 LLM 调用前(不含 LLM 时间)record;llm 路径在含 LLM 总耗时点 record。**路径归类规则**注明在代码注释中
- [x] 5.4 扩展 `/waf2/stats` 与 `/waf2/dashboard` 响应:新增 `per_path_latency` 字段(其它字段不动,对应既有 WAF2-43 / WAF2-44 仅做字段增量)
- [x] 5.5 扩展 `POST /waf2/reset`:同时调用 `path_tracker.reset()`(对应既有 WAF2-46 字段增量)
- [x] 5.6 新增单元测试 `waf2/tests/test_path_latency_tracker.py`:覆盖 spec 三个 scenario(各路径计数、窗口溢出、reset 清空)
- [x] 5.7 (可选)在 `waf2/tests/test_stats_api.py` 加一条端到端测试:发请求后 GET `/waf2/stats` 看到对应路径 `count` 增加

## 6. 切口 5 — LLM 并发上限 Semaphore (D5)

涉及:`waf2/waf2_proxy.py` LLM 调用包裹层

- [x] 6.1 模块级创建 `asyncio.Semaphore(config.llm_concurrency)`(默认 8);Semaphore 实例化时机:容器启动期,首次 LLM 调用前
- [x] 6.2 在「实际发起 LLM HTTP 调用」处 `async with semaphore`(必须在 LLMCache single-flight 创建 Future 之后、`httpx_client.post` 之前)
- [x] 6.3 文档化:运行期改 `LLM_CONCURRENCY` 配置「下次启动生效」;`/waf2/config` POST 接受该字段但不重建 Semaphore(本提案不要求热改)
- [x] 6.4 新增单元测试 `waf2/tests/test_llm_semaphore.py`:
  - `LLM_CONCURRENCY=2` + 3 个不同 key 并发 → 同时在飞的 LLM 调用 ≤ 2,所有请求最终完成
  - `LLM_CONCURRENCY=1` + 5 个同 key 并发 → 实际 LLM 调用 == 1,信号量只占用 1 次

## 7. stats 审计与契约保留 (D6 + 现有 WAF2 行为)

- [x] 7.1 全量审计 `waf2/waf2_proxy.py` 中所有 `stats[...]` 访问点,确认无 `读 → await → 写` 复合操作;若有,局部 `asyncio.Lock` 修复(预期无需)
- [x] 7.2 跑既有 `waf2/tests/` 全套用例确认无回归(尤其拦截响应格式 WAF2-30/31、PASS/BLOCK/ERROR 三态 WAF2-23、Provider 三格式 WAF2-20、LLMCache 行为 WAF2-25~28)
- [x] 7.3 用 curl 手动验证现有 API 响应结构(stats / dashboard / detections / config / reset / health),除新增 `per_path_latency` 字段外其余字段名与类型完全保持

## 8. 并发烟雾测试(RQ5 核心证据)

涉及:`waf2/tests/test_concurrency_smoke.py`(新建)

- [x] 8.1 用 `httpx.AsyncClient` 在测试进程内并发打 100 个 stage0 payload + 1 个慢 LLM payload(mock LLM 1s 延迟),验证 stage0 路径 P95 ≤ 50ms(spec scenario「长 LLM 调用不应拖慢同期 stage0 请求」)
- [x] 8.2 同测试用 20 并发同 cache key 验证 LLM 实际调用次数 == 1(覆盖 single-flight)
- [x] 8.3 `pytest --durations=0` 输出附加到 PR 描述,作为 RQ5 实验前可信度证据

## 9. 文档与配置说明

- [x] 9.1 在 `waf2/README.md` (若存在) 或 `waf2/waf2_proxy.py` 顶部 docstring 中追加配置说明:`LLM_CONCURRENCY` / `PATH_LATENCY_WINDOW` / `THREADPOOL_MAX_WORKERS` 三项与默认值
- [x] 9.2 在 `config/guardrails-config.json` 的 `waf2` 段更新示例值(实际值由读取时回退默认,无破坏)
- [x] 9.3 验证 Docker 镜像重建无错:`docker compose build waf2 && docker compose up -d waf2 && curl localhost:8081/waf2/health` 应返回 OK
- [x] 9.4 验证新 stats 字段:`curl localhost:8081/waf2/stats | jq .per_path_latency` 出现完整四路径结构

## 10. 收尾与归档

- [x] 10.1 `openspec validate improve-waf2-concurrency-for-rq5 --strict` 通过
- [x] 10.2 PR 描述贴 task 8.3 的并发烟雾测试结果与 `/waf2/stats` curl 输出
- [x] 10.3 通知姊妹提案 `add-waf2-rq5-perf-eval-harness` 可启动(切口 4 的 `per_path_latency` 字段已就绪)
