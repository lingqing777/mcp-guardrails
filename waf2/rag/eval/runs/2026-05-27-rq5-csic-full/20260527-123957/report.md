# WAF2 RQ5 性能评测报告

> ⚠️ 稳态未达成 — 实际稳态 RPS 偏差 > 5% 或 P95 抖动 > 10%,以下数据仅供参考。
> 实际稳态 RPS: 43.91 (target=50.00)
> P95 抖动: 0.01%

## 表 5.8 WAF2 大规模数据面性能指标

| 指标 | 数值 |
| --- | --- |
| 稳态平均 QPS | 43.91 |
| Avg 延迟 (ms) | 24.55 |
| P50 延迟 (ms) | 12.95 |
| P95 延迟 (ms) | 21.93 |
| P99 延迟 (ms) | 32.77 |
| CPU 占用 (%) | 35.32 |
| 内存占用 (MB) | 250.00 |
| 缓存命中率 (%) | 97.30 |


## 路由比例

| 路由 | 计数 | 占比 |
| --- | ---: | ---: |
| static_block | 4158 | 52.9% |
| fast_pass | 3493 | 44.5% |
| knowledge_evidence | 0 | 0.0% |
| local_llm_one_shot | 202 | 2.6% |
| react_deep_inspection | 2 | 0.0% |
| fallback | 1 | 0.0% |
| **合计** | **7856** | **100.0%** |


## 分路径分桶延迟

| 路径 | count | P50 (ms) | P95 (ms) | P99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| stage0 | 1024 | 1.215 | 2.730 | 3.372 |
| local_only | 1024 | 0.490 | 2.236 | 2.674 |
| rag | 0 | — | — | — |
| llm | 194 | 27989.514 | 248635.189 | 293943.279 |


## Run metadata

- target_rps: 50.0
- steady window: [93321..393992] ms (300.7s)
- driver samples (success in steady): 13201
- sampler mode: docker-stats
- sampler rows (steady): 82
