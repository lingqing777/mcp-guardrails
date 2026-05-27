## ADDED Requirements

### Requirement: 压测 driver 在 CSIC-HTTP 数据集上施压并记录 per-request 延迟
WAF2 性能评测 driver (`waf2/rag/eval/perf/rq5_driver.py`) MUST 支持加载 CSIC-HTTP 数据集 payload(优先复用既有加载逻辑;若不可用则在 perf 模块内实现最小化 loader,读取 `waf2/rag/eval/csic2010/csic_database.csv` 的 method/path/body/header 字段),并基于 `httpx.AsyncClient` + `asyncio.gather` 异步并发地把这些请求打到 WAF2 `:8081` endpoint。

driver MUST 按以下协议施压:
1. **warmup_ladder 阶段**:RPS 从起点(默认 50)按阶梯升到 `--target-rps`,每档持续 `--ladder-step-seconds`(默认 30s)
2. **steady 阶段**:维持 `--target-rps` 持续 `--steady-seconds`(默认 300s)
3. **cooldown 阶段**:停止发起新请求,等待 `--cooldown-seconds`(默认 10s) 让 in-flight 请求结束

RPS 控制 MUST 使用 token-bucket 或等价机制,实际平均 RPS 在每个阶段 MUST 与目标值偏差 ≤ 5%(报告时验证,driver 不做早停)。

driver MUST 输出以下产物到 `--out-dir`:
- `driver.csv`:per-request 行,列至少包含 `ts_ms`(从 driver 启动 `t0` 算的毫秒数)、`latency_ms`(从发送到收到完整响应)、`status`(HTTP 状态码)、`success`(布尔,2xx 或 4xx 都算 success;5xx 与超时算 failure)、`phase`(`warmup`/`steady`/`cooldown`)
- `run.json`(driver 部分):记录 `t0_unix_ts`、`target_rps`、`ladder` 各档目标 RPS 与起止时间戳、`steady_start_ms` / `steady_end_ms`、driver 版本与命令行参数

driver MUST 不修改 WAF2 数据面代码,只通过 HTTP 端点交互。

#### Scenario: 阶梯升压并产出可重放的 driver CSV
- **WHEN** 运行 `rq5_driver.py --target-rps 50 --steady-seconds 30 --ladder-step-seconds 5 --out-dir /tmp/run`,WAF2 端点 mock 为 200 OK
- **THEN** `/tmp/run/driver.csv` MUST 存在,行数 MUST > 0,所有列(ts_ms/latency_ms/status/success/phase)MUST 存在;`/tmp/run/run.json` MUST 含 `target_rps=50`、`steady_start_ms` 与 `steady_end_ms` 字段;steady 阶段实际 RPS 与 50 偏差 MUST ≤ 5%

#### Scenario: warmup 阶段标识正确
- **WHEN** driver 跑完一次完整 run
- **THEN** `driver.csv` 中 `phase` 字段 MUST 取值仅来自 `{warmup, steady, cooldown}`,且 warmup 早于 steady 早于 cooldown(按 `ts_ms` 排序)

#### Scenario: blocked 响应不算 failure
- **WHEN** WAF2 mock 返回 HTTP 403(模拟攻击 payload 被拦截)
- **THEN** driver MUST 在 driver.csv 中记录该行 `status=403`、`success=true`(因为 WAF2 成功完成判定),不算入 failure 计数

### Requirement: 资源采样脚本采集 CPU/RSS 与 WAF2 stats 时间序列
资源采样脚本 (`waf2/rag/eval/perf/rq5_sampler.py`) MUST 在 driver 施压期间并行运行,按固定间隔(默认 1s,docker stats fallback 模式默认 2s)同时采集:
1. **WAF2 容器资源**:CPU% 与 RSS(MB)
2. **WAF2 stats snapshot**:GET `http://localhost:8081/waf2/stats` 响应,提取 `cache_hits`、`llm_calls`、`per_path_latency`、`route_*` 计数等字段

sampler MUST 实现三档 fallback 选 CPU/RSS 采集方式:
- 优先级 1:`--pid <waf2_pid>` 显式 PID + `psutil`
- 优先级 2:容器名解析 — `docker inspect --format '{{.State.Pid}}' waf2` 取 PID,走 psutil
- 优先级 3(fallback):`docker stats --no-stream waf2` 解析输出

sampler MUST 输出 `sampler.csv`,列至少包含 `ts_ms`(与 driver 共享 `t0`)、`mode`(`psutil-pid`/`psutil-name`/`docker-stats`)、`cpu_pct`、`rss_mb`、`cache_hits`、`llm_calls`、`per_path_latency_json`(序列化 `/waf2/stats.per_path_latency`)。

sampler MUST 接受 `--start-at-unix-ts` 参数与 driver 共享 t0;在收到 SIGTERM/SIGINT 或运行 `--duration-seconds` 时长后优雅停止并 flush CSV。

最终 stats snapshot MUST 单独写入 `stats_final.json`(完整的 `/waf2/stats` 响应,供 report 使用)。

#### Scenario: 用 psutil 模式采集到完整时间序列
- **WHEN** sampler 以 `--pid 12345 --interval 1.0 --duration-seconds 10 --out-dir /tmp/run` 运行,WAF2 mock 端点返回 stats JSON 含 `per_path_latency` 与 `cache_hits`
- **THEN** `/tmp/run/sampler.csv` MUST 至少 8 行(10 秒 / 1 秒间隔,允许 prime 行被跳过),所有列 MUST 存在;`mode` MUST = `psutil-pid`;`per_path_latency_json` 每行 MUST 是有效 JSON

#### Scenario: docker stats fallback 强制最小 2s 间隔
- **WHEN** sampler 以 fallback 模式(`--mode docker-stats`)且 `--interval 0.5` 运行
- **THEN** sampler MUST 把 interval 提升至 2.0s 并在 stderr 警告;`sampler.csv` 中 `mode` 字段 MUST = `docker-stats`

#### Scenario: 收尾时写入 stats_final.json
- **WHEN** sampler 收到 SIGTERM 或到达 `--duration-seconds` 时长
- **THEN** `stats_final.json` MUST 包含完整 `/waf2/stats` 响应结构,其中 `per_path_latency` 字段 MUST 含 stage0/local_only/rag/llm 四桶

### Requirement: 报告生成器产出符合表 5.8 的 markdown
报告生成器 (`waf2/rag/eval/perf/rq5_report.py`) MUST 接受 driver CSV + sampler CSV + run.json + stats_final.json 作为输入,识别稳态窗口(从 `run.json.steady_start_ms` 到 `steady_end_ms`),在该窗口内计算:
1. **稳态平均 QPS** = 稳态成功响应数 / (`steady_end_ms - steady_start_ms`) * 1000
2. **Avg/P50/P95/P99 延迟(ms)** = 稳态窗口内 driver CSV `latency_ms` 列的对应统计量(用 numpy.percentile)
3. **CPU 占用 (%)** = 稳态窗口内 sampler `cpu_pct` 列的平均值
4. **内存占用 (MB)** = 稳态窗口内 sampler `rss_mb` 列的平均值
5. **缓存命中率 (%)** = (sampler 稳态尾行 `cache_hits` - 稳态首行 `cache_hits`) / max(尾-首 `cache_hits` + 尾-首 `llm_calls`, 1) * 100

输出 `report.md` MUST 包含至少三个表:
- **表 5.8 WAF2 大规模数据面性能指标**:与论文 5.6.2 节列名完全一致(指标、数值)
- **路由比例附表**:从 stats_final.json 提取 `route_static_block`、`route_fast_pass`、`route_one_shot`、`route_react` 等,展示路径占比
- **分路径分桶延迟附表**:从 stats_final.json `per_path_latency` 提取 stage0/local_only/rag/llm 四桶各自的 P50/P95/P99/count

若稳态判据未达成(实际 RPS 偏差 > 5% 或 P95 抖动 > 10%),report MUST 在 markdown 顶部用 `⚠️ 稳态未达成` 标注。

可选:若 `matplotlib` 可用,MUST 同时生成 `timeseries.png` 三联图(QPS / P95 / CPU)。无 matplotlib 时 MUST 跳过且不抛异常。

#### Scenario: 表 5.8 列名与论文一致
- **WHEN** report 用 fixture 数据生成
- **THEN** `report.md` MUST 包含 markdown 表标题 "表 5.8 WAF2 大规模数据面性能指标",且该表行 MUST 包含以下指标名(完全字符串匹配):"稳态平均 QPS"、"Avg 延迟 (ms)"、"P50 延迟 (ms)"、"P95 延迟 (ms)"、"P99 延迟 (ms)"、"CPU 占用 (%)"、"内存占用 (MB)"、"缓存命中率 (%)"

#### Scenario: 缓存命中率用稳态差值计算
- **WHEN** sampler 稳态首行 `cache_hits=100, llm_calls=20`,稳态尾行 `cache_hits=500, llm_calls=40`
- **THEN** 报告的缓存命中率 MUST = (500-100) / max((500-100) + (40-20), 1) * 100 ≈ 95.2%

#### Scenario: 稳态未达成时顶部标注
- **WHEN** 稳态实际 RPS 与 target 偏差 > 5%
- **THEN** `report.md` 顶部 MUST 出现 "⚠️ 稳态未达成" 标记,但表 5.8 仍 MUST 生成(数据有效性留给读者判断)

#### Scenario: 分路径分桶附表覆盖四桶
- **WHEN** report 用 fixture 数据生成
- **THEN** `report.md` MUST 含分路径附表,且 stage0 / local_only / rag / llm 四个 path 行 MUST 全部出现,即使某 path 在测试中无样本(此时显示 count=0 / 数值留空)

### Requirement: 一键 run 脚本归档全套产物
`waf2/rag/eval/perf/run_rq5.py` MUST 串联 driver、sampler、report 三个工具,把产物归档到:

```
waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<YYYYMMDD-HHMMSS>/
├── driver.csv
├── sampler.csv
├── stats_final.json
├── report.md
├── run.json
└── timeseries.png  (optional)
```

`run.json` MUST 包含至少:`commit_hash`(短 7 位 `git rev-parse --short HEAD`)、`timestamp`、`hostname`、`os_release`、`cpu_count`、`total_mem_mb`、`driver_args`、`sampler_args`、`steady_met`(bool,稳态判据是否达成)、`actual_steady_rps`、`p95_jitter_pct`。

run 脚本 MUST 在 sampler 与 driver 之间共享 `t0_unix_ts` 起点,确保两份 CSV 时间轴可对齐(差值 ≤ 100ms)。

#### Scenario: 完整 run 产出 6 个标准产物
- **WHEN** 执行 `run_rq5.py --target-rps 5 --steady-seconds 10` 对 mock WAF2 端点
- **THEN** 在 `waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/` 下 MUST 存在 `driver.csv`、`sampler.csv`、`stats_final.json`、`report.md`、`run.json` 五个文件;若 matplotlib 可用,`timeseries.png` MUST 额外出现

#### Scenario: run.json 含完整环境元数据
- **WHEN** run 完成后读取 `run.json`
- **THEN** MUST 至少含字段 `commit_hash` (7 字符 hex)、`timestamp` (ISO8601)、`hostname`、`cpu_count` (int > 0)、`total_mem_mb` (int > 0)、`steady_met` (bool)、`actual_steady_rps` (float)

### Requirement: 性能评测工具链不修改 WAF2 数据面
本 capability 引入的所有代码 MUST 不修改 `waf2/waf2_proxy.py`、`waf2/rag/engine.py`、`waf2/rag/knowledge_base.py`、`waf2/local_attack_score.py`、`waf2/risk_router.py`、`waf2/normalization.py`、`waf2/eval_headers.py`,以及 MCP Hub、WAF1、Dashboard 任何代码。

允许新增:
- `waf2/rag/eval/perf/*.py`(driver / sampler / report / run 与 `__init__.py`)
- `waf2/rag/eval/perf/requirements.txt`(`psutil` 等 dev 依赖)
- `waf2/tests/test_rq5_perf_harness.py`(单元 + 烟雾测试)
- `waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/*`(运行产物)

新增依赖 `psutil`、可选 `matplotlib` MUST 不进 WAF2 Docker 镜像(`waf2/requirements.txt` 不变,`waf2/Dockerfile` 不变)。

#### Scenario: WAF2 Docker 镜像依赖不变
- **WHEN** 提案落地后检查 `waf2/requirements.txt` 与 `waf2/Dockerfile`
- **THEN** 两个文件 MUST 与改造前完全一致(无 psutil/matplotlib 等新增行)

#### Scenario: 生产代码零触碰
- **WHEN** 提案落地后对生产代码做 `git diff main -- waf2/*.py waf2/rag/engine.py waf2/rag/knowledge_base.py mcp-hub/`
- **THEN** diff MUST 为空(本提案不修改任何生产源码)
