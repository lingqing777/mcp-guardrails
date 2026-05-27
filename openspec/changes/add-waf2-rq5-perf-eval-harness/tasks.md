## 1. 准备与依赖

- [x] 1.1 在 `waf2/rag/eval/perf/` 下创建模块骨架:`__init__.py`(空)与 `requirements.txt`(列出 `psutil`、可选 `matplotlib`,注明 `pandas`/`numpy` 复用项目根依赖)
- [x] 1.2 检查既有 CSIC 加载逻辑:`grep -rn "csic_database\|csic2010" waf2/ openspec/` → 若存在可复用 loader 则记录路径供 driver 调用;否则在 driver 内私有实现最小 loader
- [x] 1.3 在 `waf2/rag/eval/perf/README.md`(新建,简短)记录工具链使用方法、依赖安装命令、产物目录约定

## 2. driver — httpx 异步压测器

涉及:`waf2/rag/eval/perf/rq5_driver.py`(新建)

- [x] 2.1 实现 CSIC payload loader:从 `waf2/rag/eval/csic2010/csic_database.csv` 读 method/path/body/header 字段,支持 `--sample-size N`(默认 5000,seed 固定)与 `--full` 标志
- [x] 2.2 实现 token-bucket RPS 控制器:`async def emit_at_rps(items, rps)`,按 1/rps 秒释放 token,跨阶段切换 RPS 不丢请求队列
- [x] 2.3 实现 warmup_ladder 阶段:RPS 从 `--ladder-start`(默认 50)按阶梯到 `--target-rps`,每档 `--ladder-step-seconds`(默认 30s);记录每档起止时间戳到 `run.json.ladder`
- [x] 2.4 实现 steady 阶段:维持 `--target-rps` 持续 `--steady-seconds`(默认 300s);记录 `steady_start_ms`、`steady_end_ms`
- [x] 2.5 实现 cooldown 阶段:停止发起新请求,await 所有 in-flight 完成(超时 `--cooldown-seconds` 默认 10s)
- [x] 2.6 实现每请求记录:`ts_ms`(从 driver t0)/ `latency_ms` / `status` / `success` / `phase`,写入 `driver.csv`(用 csv.DictWriter 流式写,不积内存)
- [x] 2.7 实现 CLI 参数解析(argparse):`--target-rps`、`--steady-seconds`、`--ladder-step-seconds`、`--cooldown-seconds`、`--sample-size`、`--full`、`--out-dir`、`--waf2-url`(默认 `http://localhost:8081`)、`--start-at-unix-ts`(供 run 脚本对齐时间轴)
- [x] 2.8 输出 `run.json` driver 段:`t0_unix_ts` / `target_rps` / `ladder` / `steady_start_ms` / `steady_end_ms` / `driver_args` / `csic_seed`

## 3. sampler — 资源 + WAF2 stats 采集器

涉及:`waf2/rag/eval/perf/rq5_sampler.py`(新建)

- [x] 3.1 实现三档 fallback 选择:优先级 1 `--pid` + psutil,优先级 2 `docker inspect` 拿 PID + psutil,优先级 3 `docker stats --no-stream` 解析;CLI `--mode` 强制覆盖(auto/psutil-pid/psutil-name/docker-stats)
- [x] 3.2 实现 psutil 采集器:`Process.cpu_percent(interval=None)` 第一次返回 0,sampler MUST 在启动时 prime 一次并丢弃首样本
- [x] 3.3 实现 docker stats 解析器:`docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' waf2`,解析百分比与 RSS,fallback 模式 MUST 强制 interval ≥ 2.0s 并 stderr 警告
- [x] 3.4 实现 `/waf2/stats` 拉取器:用 `httpx.get` 同步调用 `--waf2-url/waf2/stats`(timeout 2s);失败时该样本字段填 null,不中断采样循环
- [x] 3.5 实现 sampler.csv 流式写入:`ts_ms` / `mode` / `cpu_pct` / `rss_mb` / `cache_hits` / `llm_calls` / `per_path_latency_json`(json.dumps 序列化)/ `route_static_block` / `route_fast_pass` / `route_one_shot` / `route_react`
- [x] 3.6 实现优雅停止:SIGTERM/SIGINT 或到达 `--duration-seconds` 时长后 flush CSV,GET 最后一次 `/waf2/stats` 写入 `stats_final.json`
- [x] 3.7 实现 CLI 参数:`--mode`、`--pid`、`--container-name`(默认 `waf2`)、`--interval`(默认 1.0)、`--duration-seconds`、`--out-dir`、`--waf2-url`、`--start-at-unix-ts`

## 4. report — 表 5.8 markdown 生成器

涉及:`waf2/rag/eval/perf/rq5_report.py`(新建)

- [x] 4.1 实现输入加载:driver CSV(pandas.read_csv)、sampler CSV、run.json、stats_final.json;基本字段缺失时给出可读错误
- [x] 4.2 实现稳态窗口识别:从 run.json 读 `steady_start_ms` / `steady_end_ms`,driver CSV 按 `ts_ms` 切片
- [x] 4.3 实现稳态指标计算:Avg/P50/P95/P99 用 `numpy.percentile`(线性插值);稳态平均 QPS = 稳态 success 行数 / (end - start) * 1000
- [x] 4.4 实现资源指标:稳态窗口内 sampler 行 cpu_pct/rss_mb 的 mean(跳过 prime 行,即 mode=psutil-pid 第一行)
- [x] 4.5 实现缓存命中率:稳态首尾两行 sampler 的 cache_hits 与 llm_calls 差值,公式 `(Δhits / max(Δhits + Δcalls, 1)) * 100`
- [x] 4.6 实现稳态判据评估:实际稳态 RPS 与 target_rps 偏差、30s 滚动窗口 P95 抖动;输出 `steady_met` 布尔写回 run.json
- [x] 4.7 实现 markdown 表 5.8 模板:列名与论文 5.6.2 节完全一致("稳态平均 QPS"、"Avg 延迟 (ms)"、...);稳态未达成时顶部添加 ⚠️ 标记
- [x] 4.8 实现路由比例附表:从 stats_final.json 提取 route_* 计数,展示路径占比百分比
- [x] 4.9 实现分路径分桶附表:从 stats_final.json `per_path_latency` 提取四桶 P50/P95/P99/count,无样本桶仍显示行(数值留空)
- [x] 4.10 实现 timeseries.png(可选):try-import matplotlib,Agg backend,绘制 QPS / P95 / CPU 三联图;无 matplotlib 时优雅跳过
- [x] 4.11 实现 CLI 参数:`--run-dir <dir>`(包含全部输入产物的目录)、`--target-rps`(用于稳态判据)、`--skip-plot`

## 5. run_rq5 — 一键串联脚本

涉及:`waf2/rag/eval/perf/run_rq5.py`(新建)

- [x] 5.1 实现产物目录创建:`waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<YYYYMMDD-HHMMSS>/`,本地时区时间戳,先 mkdir 再串行调度
- [x] 5.2 实现环境元数据采集:`git rev-parse --short HEAD`、`platform.platform()`、`os.cpu_count()`、`psutil.virtual_memory().total // 1024**2` 等写 `run.json` 顶层
- [x] 5.3 实现 driver + sampler 并行调度:`asyncio.create_task` 或 `subprocess.Popen` 同时启动,共享 `t0_unix_ts`(主进程取时间后注入两个 `--start-at-unix-ts`)
- [x] 5.4 实现 sampler 时长协调:sampler 的 `--duration-seconds` = ladder 总时长 + steady_seconds + cooldown_seconds + 5s 缓冲;driver 结束后等待 sampler 自然停止
- [x] 5.5 实现 report 后调用:driver/sampler 都退出后调用 `rq5_report.py --run-dir <dir> --target-rps <target>`
- [x] 5.6 实现 CLI:`--target-rps`、`--steady-seconds`、`--ladder-step-seconds`、`--out-dir`(可覆盖默认归档目录)、`--skip-plot`、`--waf2-url`

## 6. 测试 — pytest 单元 + smoke

涉及:`waf2/tests/test_rq5_perf_harness.py`(新建)

- [x] 6.1 driver 单元测试:用 `httpx.MockTransport` mock WAF2 endpoint(200 OK + 50ms artificial latency),运行 `--target-rps 10 --steady-seconds 3 --ladder-step-seconds 1 --out-dir tmp_path`;验证 driver.csv 列名、行数、phase 取值集
- [x] 6.2 driver RPS 偏差测试:跑短时长,验证 steady 实际 RPS 在 target ±5% 内
- [x] 6.3 driver blocked 响应测试:mock 返回 403,验证 success=true 而非 false
- [x] 6.4 sampler 单元测试:用 `httpx.MockTransport` mock `/waf2/stats`,运行 sampler 5s 间隔 1s;验证 sampler.csv 列名、`per_path_latency_json` 可 json.loads、`mode` 字段非空
- [x] 6.5 sampler fallback 测试:`--mode docker-stats --interval 0.5`,验证 interval 被提升到 2.0 且 stderr 有 warning
- [x] 6.6 sampler stats_final.json 测试:验证 SIGTERM/duration 到达后 `stats_final.json` 存在且含 `per_path_latency` 四桶
- [x] 6.7 report 单元测试:用 fixture driver.csv + sampler.csv + run.json + stats_final.json 跑 report;验证 report.md 含 "表 5.8 WAF2 大规模数据面性能指标" 标题与全部 8 个指标名
- [x] 6.8 report 稳态未达成测试:fixture 中实际 RPS 偏差 > 5%,验证 report.md 顶部有 "⚠️ 稳态未达成" 标记
- [x] 6.9 report 分桶附表测试:fixture stats_final.json 含 stage0/local_only/rag/llm 四桶,验证 report.md 中四个 path 行全出现
- [x] 6.10 报表数值精度测试:fixture 数据已知答案,验证缓存命中率公式输出 = (Δhits / max(Δhits + Δcalls, 1)) * 100,误差 < 0.1%
- [x] 6.11 端到端拼接 smoke 测试:用 mock WAF2,运行 `run_rq5.py --target-rps 5 --steady-seconds 3 --ladder-step-seconds 1 --skip-plot --out-dir tmp_path`;验证 tmp_path 子目录下 5 个产物(driver/sampler/stats_final/report/run.json)全部存在

## 7. 文档与示例

- [x] 7.1 `waf2/rag/eval/perf/README.md`:工具链使用方法、依赖安装(`pip install -r waf2/rag/eval/perf/requirements.txt`)、产物目录约定、典型命令行(短 smoke + 论文 RQ5 命令)
- [x] 7.2 在 `waf2/rag/eval/perf/README.md` 顶部加示例 markdown:产物 `report.md` 长什么样(表 5.8 + 路由比例 + 分桶附表的小样本)
- [x] 7.3 在 `waf2/rag/eval/perf/README.md` 说明:稳态未达成时如何调参(减小 target_rps、增长 steady_seconds、检查上游 LLM)

## 8. 真实 WAF2 烟雾验证(手动,不进 pytest)

- [x] 8.1 `docker compose build waf2 && docker compose up -d waf2`,确认 `curl localhost:8081/waf2/health` 返回 OK
- [x] 8.2 装 perf 依赖:`pip install -r waf2/rag/eval/perf/requirements.txt`
- [x] 8.3 跑短时长 smoke:`python waf2/rag/eval/perf/run_rq5.py --target-rps 5 --steady-seconds 30 --ladder-step-seconds 10 --skip-plot`
- [x] 8.4 验证 `waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/` 下五个标准产物全部存在
- [x] 8.5 打开 `report.md`,确认表 5.8 八个格子全有数值,缓存命中率字段 ∈ [0, 100],分桶附表显示了实际经过的路径

## 9. 收尾

- [x] 9.1 `openspec validate add-waf2-rq5-perf-eval-harness --strict` 通过
- [x] 9.2 运行 `git diff main -- waf2/*.py waf2/rag/engine.py waf2/rag/knowledge_base.py mcp-hub/ waf2/Dockerfile waf2/requirements.txt` 确认为空(生产代码零触碰)
- [x] 9.3 跑 RQ5 实验把产物存进 `waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/`,提交到仓库(沿用 runs 归档约定)
- [x] 9.4 把 report.md 的表 5.8 数值填回论文 5.6.2 节
