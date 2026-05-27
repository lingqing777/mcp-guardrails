# WAF2 RQ5 perf harness

`/opsx` change: [`add-waf2-rq5-perf-eval-harness`](../../../../../openspec/changes/add-waf2-rq5-perf-eval-harness/proposal.md)
Paper section: 5.6 RQ5 — 大规模数据面性能与资源开销

This directory contains the offline tooling used to fill paper Table 5.8
(稳态 QPS / Avg / P50 / P95 / P99 latency / CPU% / RSS / cache hit rate)
plus the auxiliary routing and per-path latency breakdowns required by
section 5.6.4.

## Layout

```
waf2/rag/eval/perf/
├── __init__.py
├── requirements.txt   dev-only deps (NOT installed into the WAF2 docker image)
├── rq5_driver.py      httpx async load driver — warmup ladder → steady → cooldown
├── rq5_sampler.py     psutil + /waf2/stats time-series sampler
├── rq5_report.py      merges inputs into report.md (table 5.8)
└── run_rq5.py         orchestrator — runs driver + sampler in parallel, then report
```

Outputs land under
```
waf2/rag/eval/runs/2026-05-27-rq5-csic-full/<YYYYMMDD-HHMMSS>/
```

## Installation

```bash
pip install -r waf2/rag/eval/perf/requirements.txt
```

`psutil` is required; `matplotlib` is optional (timeseries.png is skipped without it).
None of these dependencies are bundled into the WAF2 Docker image — they live
outside the container.

## Quick smoke (mock-friendly, ~15s)

```bash
python -m waf2.rag.eval.perf.run_rq5 \
    --target-rps 5 --steady-seconds 10 \
    --ladder-start 5 --ladder-step-seconds 0 \
    --cooldown-seconds 0 --sample-size 50 \
    --skip-plot
```

If WAF2 is not running this still produces a `report.md` (with mostly-empty
data). The pytest suite (`waf2/tests/test_rq5_perf_harness.py`) covers the
component-level behavior offline using `httpx.MockTransport`.

## Paper RQ5 run (real WAF2, full pipeline)

1. `docker compose up -d waf2` and confirm `curl localhost:8081/waf2/health` → OK
2. `python -m waf2.rag.eval.perf.run_rq5 --target-rps 50 --steady-seconds 300`
3. Open the archived `report.md` to copy the 8 cells of Table 5.8 into the paper

`run_rq5.py` accepts the following knobs:

| flag | default | purpose |
| --- | --- | --- |
| `--target-rps` | required | Steady-state RPS target |
| `--steady-seconds` | 300 | How long to hold the steady plateau |
| `--ladder-start` | 50 | Initial warmup RPS (doubles toward target) |
| `--ladder-step-seconds` | 30 | Time per warmup step |
| `--cooldown-seconds` | 10 | Drain time after steady ends |
| `--sample-size` | 5000 | CSIC payloads sampled (uses `--seed` for repeatability) |
| `--full` | off | Replay the entire CSIC dataset instead of sampling |
| `--waf2-url` | `http://localhost:8081` | Target WAF2 endpoint |
| `--waf2-pid` | auto | Explicit PID for `psutil-pid` sampler mode |
| `--sampler-mode` | `auto` | `psutil-pid` / `psutil-name` / `docker-stats` |
| `--skip-plot` | off | Don't emit timeseries.png even if matplotlib is available |

## Steady-state criterion

The report applies this rule **after** the run finishes and labels the report
header with ✅ or ⚠️:

- Actual steady RPS within ±5% of `--target-rps`, **and**
- Rolling 30-second-window P95 jitter (max − min) ÷ median ≤ 10%

`driver` does not early-stop on criterion failure; if a run does not meet the
criterion, lower `--target-rps` or examine the LLM backend and rerun.

## Artifacts per run

| file | producer | purpose |
| --- | --- | --- |
| `driver.csv` | `rq5_driver` | per-request rows (ts_ms, latency_ms, status, success, phase, label) |
| `sampler.csv` | `rq5_sampler` | per-sample rows (CPU%, RSS, cache_hits, llm_calls, route_*, per_path_latency_json) |
| `stats_final.json` | `rq5_sampler` | last good `/waf2/stats` snapshot |
| `report.md` | `rq5_report` | table 5.8 + routing breakdown + per-path breakdown |
| `run.json` | `run_rq5` | env metadata (commit, hostname, cpu_count, total_mem_mb) + steady verdict |
| `run.{driver,sampler,report}.json` | each tool | tool-level metadata for traceability |
| `timeseries.png` | `rq5_report` (optional) | QPS / P95 / CPU triple plot |

## Sample report.md

```markdown
# WAF2 RQ5 性能评测报告

> ✅ 稳态达成 — 实际稳态 RPS 50.21 (target=50.00), P95 抖动 3.42%

## 表 5.8 WAF2 大规模数据面性能指标

| 指标 | 数值 |
| --- | --- |
| 稳态平均 QPS | 50.21 |
| Avg 延迟 (ms) | 8.43 |
| P50 延迟 (ms) | 5.10 |
| P95 延迟 (ms) | 22.30 |
| P99 延迟 (ms) | 480.20 |
| CPU 占用 (%) | 34.12 |
| 内存占用 (MB) | 215.40 |
| 缓存命中率 (%) | 78.21 |

## 路由比例
...

## 分路径分桶延迟
...
```
