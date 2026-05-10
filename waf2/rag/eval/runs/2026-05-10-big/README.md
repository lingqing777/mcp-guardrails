# Eval Run: CSIC 500 + 1000 大规模评测 2026-05-10

## 环境

- Commit: `727c663`
- Model: `qwen3:8b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 500 (RAG OFF) | CSIC 500 (RAG ON) | CSIC 1000 (RAG OFF) | CSIC 1000 (RAG ON) |
|------|---------------------|--------------------|----------------------|---------------------|
| Precision | 1.000 | 1.000 | 1.000 | 1.000 |
| Recall | 0.754 | 0.754 | 0.723 | 0.723 |
| F1 | 0.860 | 0.860 | 0.839 | 0.839 |
| FPR | 0.000 | 0.000 | 0.000 | 0.000 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Valid | YES | YES | YES | YES |

### RAG 统计

| 指标 | CSIC 500 RAG ON | CSIC 1000 RAG ON |
|------|-----------------|------------------|
| RagQuery | 43 | 101 |
| RagHit | 8 | 24 |
| RagEmpty | 35 | 77 |
| RagGated | 8 | 24 |
| RagPositive | 8 | 24 |
| RAG 命中率 | 18.6% | 23.8% |

### 路由分布 (CSIC 1000 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 640 |
| Fast-pass | 506 |
| Local LLM | 93 |
| React | 8 |
| Local Block | 616 |

## 样本量 vs Recall 趋势

| 样本量 | Recall (RAG OFF) |
|--------|------------------|
| 100 | 0.850 |
| 250 | 0.788 |
| 500 | 0.754 |
| 1000 | 0.723 |

Recall 随样本量增加而下降，说明 small sample 高估了真实性能。

## 文件

- `results-csic-500.md` — CSIC 500 评测报告
- `results-csic-1000.md` — CSIC 1000 评测报告
- `failures-csic-500.jsonl` — CSIC 500 失败样本
- `failures-csic-1000.jsonl` — CSIC 1000 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
