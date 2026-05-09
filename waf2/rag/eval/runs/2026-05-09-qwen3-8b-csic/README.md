# Eval Run: qwen3:8b + CSIC 2026-05-09

## 环境

- Commit: `727c663`
- Model: `qwen3:8b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 100 (RAG OFF) | CSIC 100 (RAG ON) | CSIC 250 (RAG OFF) | CSIC 250 (RAG ON) |
|------|---------------------|--------------------|---------------------|--------------------|
| Precision | 1.000 | 1.000 | 1.000 | 1.000 |
| Recall | 0.850 | 0.850 | 0.788 | 0.788 |
| F1 | 0.919 | 0.919 | 0.881 | 0.881 |
| FPR | 0.000 | 0.000 | 0.000 | 0.000 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Valid | YES | YES | YES | YES |

### RAG 统计 (CSIC 250 RAG ON)

| 指标 | 值 |
|------|-----|
| RagQuery | 26 |
| RagHit | 6 |
| RagEmpty | 20 |
| RagGated | 6 |
| RagPositive | 6 |
| RagBenign | 0 |

## 与 e9cd555 对比

- CSIC 100: R 0.810 → 0.850 (+4pp)
- CSIC 250: R 0.744 → 0.788 (+4pp)
- Static Block 增加：172→182 (CSIC 250)
- Fast-pass 减少：126→117 (CSIC 250)

## 路由分布 (CSIC 250 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 182 |
| Fast-pass | 117 |
| Local LLM | 24 |
| React | 2 |
| Local Block | 176 |

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
