# Eval Run: qwen2.5:1.5b + CSIC 2026-05-06 (RAG ON)

## 环境

- Commit: `aa8ce3e`
- Model: `qwen2.5:1.5b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60) — 本次 RAG 正常加载
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 100 (RAG OFF) | CSIC 100 (RAG ON) | CSIC 250 (RAG OFF) | CSIC 250 (RAG ON) |
|------|---------------------|--------------------|---------------------|--------------------|
| Precision | 1.000 | 0.972 | 1.000 | 0.947 |
| Recall | 0.700 | 0.700 | 0.640 | 0.640 |
| F1 | 0.824 | 0.814 | 0.780 | 0.764 |
| FPR | 0.000 | 0.020 | 0.000 | 0.036 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Valid | YES | YES | YES | YES |

### RAG 统计 (CSIC 250 RAG ON)

| 指标 | 值 |
|------|-----|
| RagQuery | 34 |
| RagHit | 11 |
| RagEmpty | 23 |
| RagGated | 8 |
| RagPositive | 11 |
| RagBenign | 0 |

## 路由分布 (CSIC 250 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 142 |
| Fast-pass | 146 |
| Local LLM | 31 |
| React | 3 |
| Local Block | 132 |

## 主要发现

1. RAG 正常工作但引入误报（FPR=0.036）
2. RAG 命中率仅 32%（11/34），知识库覆盖不足
3. RAG 对 Recall 无提升，仅增加 FP

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
