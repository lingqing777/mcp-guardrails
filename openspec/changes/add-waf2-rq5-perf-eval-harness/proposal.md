## Why

姊妹提案 `improve-waf2-concurrency-for-rq5` 已让 WAF2 数据面在并发下产出可信的延迟与缓存命中率指标(单进程 asyncify + 单飞缓存 + `per_path_latency` 分桶);但论文 RQ5(5.6 节)要填的表 5.8 还需要**外部测量**:在 CSIC-HTTP 数据集上以 warmup-阶梯 + 稳态协议施压,采集容器级 CPU/RSS,把 driver 测得的延迟 + WAF2 内部 stats + 资源采样 合并成可重复、可附论文的报告。

当前缺口三件:
1. **没有可重复的压测 driver** — 既有 `waf2/rag/eval/runs/` 系列是检测正确性评测(F1/Precision/Recall),没有性能采集
2. **没有资源采样工具** — CPU/内存是表 5.8 必填,WAF2 自身不暴露这两个指标,需要外挂 psutil 或 `docker stats` 采集
3. **没有报告生成器** — driver CSV + sampler CSV + WAF2 stats JSON 三路数据手动汇总易错且不可重现

落地后即可一键跑出 RQ5 实验结果,验证 5.6.4 三个观察重点:(a) 普通硬件可持续运行;(b) 大多数请求在本地快速路径完成;(c) 模型路径未成主吞吐瓶颈。

## What Changes

- 新增 **httpx 异步压测 driver**(`waf2/rag/eval/perf/rq5_driver.py`):加载 CSIC payload,按 warmup-阶梯 + 稳态协议并发打 WAF2 `:8081`,记录 per-request 延迟 CSV + run metadata JSON
- 新增 **资源采样脚本**(`waf2/rag/eval/perf/rq5_sampler.py`):固定间隔采 WAF2 容器 CPU% / RSS(psutil 优先,fallback 到 `docker stats --no-stream`),同时拉 `/waf2/stats` snapshot(消费 `per_path_latency`、`cache_hits`、`llm_calls`、路由计数)
- 新增 **报告生成器**(`waf2/rag/eval/perf/rq5_report.py`):合并三路输入,产出 `report.md` 含表 5.8 + 路由比例附表 + 分路径分桶延迟附表,(可选)`.png` 时间序列图
- 新增 **一键 run 脚本**(`waf2/rag/eval/perf/run_rq5.py`):串联 driver + sampler + report,产物归档到 `waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<timestamp>/`,写入 `run.json` 含 commit hash / 配置 / 机器规格
- 新增 **perf 模块依赖**(`waf2/rag/eval/perf/requirements.txt`):psutil(新增 dev 依赖);numpy/pandas(已存在,声明 perf 模块用途);matplotlib(可选,有图时启用)
- 新增 **单元 + 烟雾测试**(`waf2/tests/test_rq5_perf_harness.py`):用 `httpx.MockTransport` mock WAF2 端点,验证 driver/sampler/report 拼接与 CSV/markdown 输出正确性

## Capabilities

### New Capabilities
- `waf2-perf-eval`: WAF2 性能评测工具链能力(driver / sampler / report / run 脚本与压测协议)。新建 `openspec/specs/waf2-perf-eval/spec.md`

### Modified Capabilities

无既有 capability 的 spec-level 行为变化。本提案完全是新工具,不修改 WAF2 数据面、Dashboard、MCP Hub、WAF1 或 既有 `waf2` capability 的 requirements。

## Impact

- **影响范围**(纯新增,零接触生产代码):
  - 新建 `waf2/rag/eval/perf/`(driver / sampler / report / run / requirements)
  - 新建 `waf2/tests/test_rq5_perf_harness.py`
  - 新建 `openspec/specs/waf2-perf-eval/spec.md`(随归档时合并)
- **不影响**:
  - `waf2/waf2_proxy.py` 与生产数据面 — 本提案是外部观测,只读 `/waf2/stats`,不修改服务端
  - MCP Hub / Dashboard / WAF1 / 路由顺序 / 认证边界 — 零触碰
  - 既有 `waf2/rag/eval/runs/` 检测正确性评测 — 共存于 `runs/` 目录下不同子目录
- **依赖与版本**:
  - 新增 `psutil`(资源采样必须;只在 perf 工具链使用,不进 WAF2 容器镜像)
  - 复用 `httpx`、`numpy`、`pandas`(项目已有)
  - 可选 `matplotlib`(只在生成时间序列图时引入,运行时通过 try-import 优雅降级)
- **结果产物**(每次 run):
  - `driver.csv`(per-request 延迟)
  - `sampler.csv`(资源 + WAF2 stats 时间序列)
  - `report.md`(表 5.8 + 分桶附表)
  - `run.json`(环境元数据)
  - 可选 `timeseries.png`
- **风险**:
  - psutil 跨平台(Linux/macOS/Windows)取 docker 容器 PID 的方式不同 → driver 提供 `--pid` 显式参数与 `docker stats` 兜底两条路径
  - matplotlib 在 headless CI 上的 backend 兼容 → 用 `Agg` backend,避免依赖 DISPLAY
- **后续提案**:本提案是 RQ5 工具链终点;落地后可直接跑实验填表 5.8,无后续依赖
