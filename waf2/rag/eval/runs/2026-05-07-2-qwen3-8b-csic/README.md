# Eval Run: qwen3:8b + CSIC 2026-05-07 (v2)

## 环境

- Commit: `e9cd555`
- Model: `qwen3:8b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 100 (RAG OFF) | CSIC 100 (RAG ON) | CSIC 250 (RAG OFF) | CSIC 250 (RAG ON) |
|------|---------------------|--------------------|---------------------|--------------------|
| Precision | 1.000 | 1.000 | 1.000 | 1.000 |
| Recall | 0.810 | 0.810 | 0.744 | 0.744 |
| F1 | 0.895 | 0.895 | 0.853 | 0.853 |
| FPR | 0.000 | 0.000 | 0.000 | 0.000 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Valid | YES | YES | YES | YES |

### RAG 统计 (CSIC 250 RAG ON)

| 指标 | 值 |
|------|-----|
| RagQuery | 27 |
| RagHit | 6 |
| RagEmpty | 21 |
| RagGated | 6 |
| RagPositive | 6 |
| RagBenign | 0 |

## 与 8c6168d 对比

- CSIC 100: R 0.700 → 0.810 (+11pp)
- CSIC 250: R 0.640 → 0.744 (+10pp)
- Static Block 数量增加：146→172，e9cd555 新增 pattern 效果显著
- Fast-pass 减少：150→126，更多攻击被 static 拦截
- Valid=True，LlmErr=0

## 路由分布 (CSIC 250 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 172 |
| Fast-pass | 126 |
| Local LLM | 25 |
| React | 2 |
| Local Block | 166 |

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
