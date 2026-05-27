# WAF2 RQ5 性能评测报告

> ⚠️ 稳态未达成 — 实际稳态 RPS 偏差 > 5% 或 P95 抖动 > 10%,以下数据仅供参考。
> 实际稳态 RPS: 4.94 (target=5.00)
> P95 抖动: 148.43%

## 表 5.8 WAF2 大规模数据面性能指标

| 指标 | 数值 |
| --- | --- |
| 稳态平均 QPS | 4.94 |
| Avg 延迟 (ms) | 1161.49 |
| P50 延迟 (ms) | 13.41 |
| P95 延迟 (ms) | 10174.42 |
| P99 延迟 (ms) | 22551.65 |
| CPU 占用 (%) | 8.30 |
| 内存占用 (MB) | 217.28 |
| 缓存命中率 (%) | 97.89 |


## 路由比例

| 路由 | 计数 | 占比 |
| --- | ---: | ---: |
| static_block | 13 | 29.5% |
| fast_pass | 28 | 63.6% |
| knowledge_evidence | 0 | 0.0% |
| local_llm_one_shot | 3 | 6.8% |
| react_deep_inspection | 0 | 0.0% |
| fallback | 0 | 0.0% |
| **合计** | **44** | **100.0%** |


## 分路径分桶延迟

| 路径 | count | P50 (ms) | P95 (ms) | P99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| stage0 | 39 | 0.810 | 2.413 | 3.250 |
| local_only | 96 | 0.466 | 2.240 | 2.900 |
| rag | 0 | — | — | — |
| llm | 12 | 10101.566 | 23014.872 | 25579.542 |


## Run metadata

- target_rps: 5.0
- steady window: [2483..32675] ms (30.2s)
- driver samples (success in steady): 149
- sampler mode: docker-stats
- sampler rows (steady): 8
