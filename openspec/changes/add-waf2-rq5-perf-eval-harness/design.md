## Context

RQ5(5.6 节)要在 CSIC-HTTP 数据集上评测 WAF2 数据面的实时性与资源开销,目标是填出表 5.8 共 8 行:稳态平均 QPS、Avg/P50/P95/P99 延迟、CPU%、内存 MB、缓存命中率,并验证 5.6.4 三个观察重点 ((a) 普通硬件可持续运行;(b) 大多数请求走本地快速路径;(c) 模型路径不是主吞吐瓶颈)。

姊妹提案 `improve-waf2-concurrency-for-rq5` 已让 WAF2 数据面在并发下指标可信:
- `/waf2/stats` 暴露 `per_path_latency` 字段(stage0/local_only/rag/llm 四桶 P50/P95/P99/count)
- LLMCache 做了 single-flight,缓存命中率不再被并发 miss 风暴低估
- async LLM + to_thread 让事件循环不再被慢 LLM 阻塞,P95 反映系统设计而非阻塞

本提案是 RQ5 工具链的**外部测量**那一段。结构:三个独立可单测的脚本(driver / sampler / report)+ 一个串联它们的 run 脚本,产物归档到 `waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/`。

约束:
- 本地部署,面向裁判演示与论文实验,**不**追求生产级压测平台
- 不引入 Prometheus/Grafana(单运行单产物,CSV+markdown 足够)
- 不改 WAF2 数据面、Dashboard、MCP Hub、WAF1
- 既有 `waf2/rag/eval/runs/<date>-<topic>/` 命名约定保持(年月日 + 主题)
- 输出格式必须与论文表 5.8 列名完全一致(避免论文写作时手工对齐)

## Goals / Non-Goals

**Goals:**
- 在 CSIC-HTTP 数据集上,以 warmup-阶梯 + 定时长稳态协议对 WAF2 full pipeline 施压,记录 per-request 延迟 CSV
- 同步采样 WAF2 容器 CPU% / RSS / `/waf2/stats` snapshot,按固定间隔写入 sampler CSV
- 一键产出 `report.md`(含表 5.8 + 路由比例 + 分路径分桶延迟附表),数据可重复
- 4 个脚本独立可单测(`pytest waf2/tests/test_rq5_perf_harness.py`)
- 一键 run 脚本 `run_rq5.py` 串联三者,把全套产物归档到带时间戳子目录

**Non-Goals:**
- 多机分布式压测(本地裁判演示,单机就够)
- 长耐力测试(>1h):本提案稳态 ≥ 5min 已满足统计意义
- 改 WAF2 数据面代码(由提案 1 完成)
- Dashboard UI 改动(本提案的输出是论文用的 markdown 表,不进 Dashboard)
- Prometheus / Grafana / OpenTelemetry 集成(单运行场景,过度工程)
- 跨数据集泛化(本提案专为 CSIC-HTTP,其它数据集若需要,日后另起提案)
- 真实 LLM 调用绑定(driver 是负载产生器,WAF2 怎么调 LLM 由 WAF2 自己决定)

## Decisions

### D1. driver 用 httpx.AsyncClient + asyncio,不用 wrk/hey

`waf2/rag/eval/perf/rq5_driver.py` 用 `httpx.AsyncClient` + `asyncio.gather` + `asyncio.Semaphore` 控制并发。原因:
- 项目已有 `httpx` 依赖,统一栈
- CSIC payload 是 HTTP 请求(method/path/body),需要从 CSV 加载并按字段重放 — 用 Python 生成器更顺手
- wrk/hey 难以重放任意 HTTP body 与自定义 header,且需要外部安装
- 需要每请求精确 RPS 控制(token bucket / fixed interval),Python 直接实现简洁

**替代方案**:
- `locust` — 框架较重,引入额外配置文件,RQ5 单跑用不上;弃
- `aiohttp` — 项目未用,引入额外依赖与风格分裂;弃

**RPS 控制**:用 simple token bucket(每 1/RPS 秒释放一个 token),不追求 microsecond 级精度,只保证均值在 ±5% 内。

### D2. CSIC 数据集加载复用既有路径

CSIC payload 文件位于 `waf2/rag/eval/csic2010/csic_database.csv`(实测存在)。driver 新增一个轻量 loader 把 CSV 行转换成 HTTP method/path/body/headers,**不重写**既有评测脚本的 loader。如果发现既有 loader 可直接复用,优先复用;否则在 perf 模块内私有实现(简短,~50 行)。

**抽样策略**:driver 提供 `--sample-size` 参数,默认从 CSIC 完整集中随机抽样 ~5000 条(seed 固定保证可重复),足够稳态 5min @ 50 RPS(15000 请求)循环利用。`--full` 标志可改成全集。

### D3. warmup-阶梯 + 稳态判据

**协议**:
```
阶段 1 warmup_ladder: 50 RPS → 100 RPS → ... → target RPS,每档 30s
阶段 2 steady:        持续 ≥ steady_seconds (默认 300s) @ target RPS
阶段 3 cooldown:      停 10s,等 in-flight 请求 drain
```

**稳态判据(报告时用,不是 driver 早停条件)**:稳态窗口内,实际 RPS 与 target RPS 偏差 ≤ 5% **且** 滚动 30s 窗口的 P95 抖动 ≤ 10%。如果未达稳态,report 会在 markdown 顶部红字标注「稳态未达成,数据仅供参考」。

**原因**:driver 不做早停是为了让 driver/sampler 跑完整时长,数据后处理(report)再判稳态;这让 driver 简单且可重跑。

### D4. 资源采样三档 fallback

`rq5_sampler.py` 按优先级:
1. **psutil + PID**(`--pid <waf2_pid>`):最准确,直接读 `/proc/<pid>/stat`,跨进程开销低
2. **psutil + 容器名解析**(默认):用 `docker inspect --format '{{.State.Pid}}' waf2` 拿 PID,再走 psutil
3. **docker stats --no-stream**:不依赖 psutil,但每次启动新进程开销大,采样间隔不宜小于 2s

**采样间隔**:默认 1s(psutil),docker stats 模式下默认 2s。所有时间戳用 `time.monotonic()` 相对零点,确保 driver/sampler 时间轴可对齐。

**WAF2 stats 拉取**:同样 1s 间隔 GET `/waf2/stats`,响应进 sampler CSV 的 `per_path_latency_json` 与 `cache_hit_rate` 列;driver 与 sampler 进程共享同一 `t0`,通过 `--start-at-unix-ts` 参数对齐。

### D5. 报告生成器的稳态选窗逻辑

`rq5_report.py` 输入 driver CSV + sampler CSV + run metadata,流程:
1. 从 run.json 读 warmup 时长,从该时间戳之后开始算稳态
2. 计算稳态窗口内每请求延迟 → Avg/P50/P95/P99(总体)
3. 从 sampler CSV 末端最近一次 `/waf2/stats` snapshot 提取 `per_path_latency`(分路径) 与 `cache_hit_rate`
4. 资源用稳态窗口内 sampler 行 → CPU% 平均、RSS 平均
5. 实际 QPS = 稳态窗口内成功响应数 / 稳态时长
6. 输出 `report.md`,**表 5.8 列名与论文 5.6.2 节完全一致**

**为什么用 sampler 末端 stats 而非自己重算 hit rate**:WAF2 内部 `cache_hits` 与 `llm_calls` 是从启动起累计,稳态窗口的 hit rate 应该是「窗口结束时 - 窗口开始时」差值;sampler 在每个采样点都记录这两个值,report 取窗口起止两行做差即可。

### D6. 输出目录约定

```
waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/
├── driver.csv          per-request: {ts_ms, latency_ms, status, success}
├── sampler.csv         per-sample: {ts_ms, cpu_pct, rss_mb, cache_hits, llm_calls, per_path_latency_json}
├── stats_final.json    /waf2/stats 收尾 snapshot (最完整的 per_path_latency)
├── report.md           表 5.8 + 路由比例 + 分桶附表
├── run.json            commit hash / 配置 / 机器规格 / 实际 RPS / 稳态判据结果
└── timeseries.png      (可选) QPS / P95 / CPU 三联时序图
```

**`<timestamp>`**: `YYYYMMDD-HHMMSS`(本地时区),与 commit hash 短 7 位并列写进 `run.json`,便于复盘。

### D7. 测试策略 — mock 后端,不依赖真实 WAF2 容器

`waf2/tests/test_rq5_perf_harness.py` 用:
- `httpx.MockTransport` mock WAF2 `/waf2/stats` 与 `/<path:path>` 端点,driver 不连真实 WAF2 也能跑(返回 200 OK)
- 用 `tmp_path` fixture 把产物写到临时目录,验证 CSV 列名/类型与 markdown 结构
- 短时长(2s warmup + 5s steady)smoke 跑,验证 driver+sampler+report 拼接逻辑无 raise

**真实 WAF2 烟雾测试**(`run_rq5.py --target-rps 5 --steady-seconds 30`)由开发者手动跑,作为提案归档前的最终验证,**不放进 pytest 自动化**(避免 CI 依赖 Docker)。

### D8. matplotlib 选用 backend Agg + try-import

`rq5_report.py` 顶部:
```python
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except Exception:
    HAS_MPL = False
```

无 matplotlib 时跳过时序图生成,markdown 仍正常产出。这让 perf 模块在裸 Python 环境也能跑。

## Risks / Trade-offs

- **[风险] docker stats 模式下采样开销大** → sampler 检测到 fallback 模式时强制最小间隔 2s,并在 sampler CSV 与 report 中标注 mode 字段;开发者可以选择装 psutil 取得 1s 精度
- **[风险] CSIC payload 中存在攻击样本被 WAF2 拦截,影响 QPS 测量** → driver 接受 `--include-blocked` 默认 True;blocked 也算成功完成响应(只是 HTTP 403),计入 QPS 与延迟;report 在表 5.8 下方附 `block_rate` 指标作为辅助
- **[风险] LLM 后端慢,稳态难以达成** → driver/report 不强制稳态判据,只在 report 顶部标注;如果未达稳态,开发者可调小 `--target-rps` 重跑
- **[风险] CSIC 数据集编码或字段格式与既有 loader 不兼容** → driver 内置最小化 loader,只读 method/path/body/header 几个字段,缺失字段用安全默认;不通过既有 loader 链路,避免间接依赖
- **[风险] httpx.AsyncClient 在 4000+ QPS 下可能成为瓶颈** → 本提案目标 RQ5 是 50-200 RPS 量级,httpx 足够;若未来要 4000+,需要切换 driver 实现,届时另起提案
- **[Trade-off] 不做实时 dashboard** → 单次 run,产物是论文用,markdown 足够;Dashboard 实时观察需求由开发者用 `watch -n 1 'curl localhost:8081/waf2/stats | jq .per_path_latency'` 临时满足
- **[Trade-off] driver 用 token-bucket 控 RPS,微观抖动较高** → 报告稳态判据用 30s 滚动窗口,微观抖动会被平均,实际 QPS 平均仍在 ±5% 内;对论文表 5.8 足够
- **[未决问题] sampler 的 cpu% 计算窗口** → psutil `Process.cpu_percent(interval=None)` 用上次调用以来的时间差;sampler 第一次调用要 prime 一次(返回 0),report 应跳过第一行
- **[未决问题] 是否要同时跑多个 target_rps 自动 sweep** → 暂不做;单跑足够,sweep 留作未来提案;`run_rq5.py` 用外层 shell loop 即可手工实现 sweep

## Migration Plan

纯新增工具,无数据迁移、无回滚需求:
1. 实施时按 tasks.md 顺序合入 4 个脚本 + 1 个测试文件
2. 新依赖 `psutil` 加入 `waf2/rag/eval/perf/requirements.txt`(不进 WAF2 容器),开发者用 `pip install -r waf2/rag/eval/perf/requirements.txt` 装
3. 首次实验前手动跑短时长 smoke(`run_rq5.py --target-rps 5 --steady-seconds 30`)验证全链路
4. 跑 RQ5 实验把产物存进 `waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/`,提交到仓库(沿用既有 runs 归档约定)
5. 回滚策略:删除 `waf2/rag/eval/perf/` 即可,不影响其它模块
