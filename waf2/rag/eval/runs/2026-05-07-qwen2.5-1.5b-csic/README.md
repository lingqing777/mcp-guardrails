# Eval Run: qwen2.5:1.5b + CSIC 2026-05-07

## 环境

- Commit: `8c6168d`
- Model: `qwen2.5:1.5b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 100 (RAG OFF) | CSIC 100 (RAG ON) | CSIC 250 (RAG OFF) | CSIC 250 (RAG ON) |
|------|---------------------|--------------------|---------------------|--------------------|
| Precision | 1.000 | 1.000 | 1.000 | 1.000 |
| Recall | 0.700 | 0.700 | 0.640 | 0.640 |
| F1 | 0.824 | 0.824 | 0.780 | 0.780 |
| FPR | 0.000 | 0.000 | 0.000 | 0.000 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Valid | YES | YES | YES | YES |

### RAG 统计 (CSIC 250 RAG ON)

| 指标 | 值 |
|------|-----|
| RagQuery | 30 |
| RagHit | 7 |
| RagEmpty | 23 |
| RagGated | 7 |
| RagPositive | 7 |
| RagBenign | 0 |

## 与上次对比 (aa8ce3e)

- 8c6168d 修复了 qwen2.5:1.5b RAG ON 的误报问题（上次 FP=9，本次 FP=0）
- RAG 命中率仍低：30 次查询仅 7 次命中
- Fast-pass 数量略增（146→150），可能是 risk_router.py 变更导致

## 主要发现

1. 8c6168d 修复了 RAG 引入的误报，Precision 恢复 1.000
2. RAG 对 Recall 仍无提升，命中率仅 23%（7/30）
3. qwen2.5:1.5b 与 qwen3:8b 在 CSIC 上指标一致

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
