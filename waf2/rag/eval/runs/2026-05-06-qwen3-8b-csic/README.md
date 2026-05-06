# Eval Run: qwen3:8b + CSIC 2026-05-06

## 环境

- Commit: `bf0f4e1`
- Model: `qwen3:8b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 100 (RAG OFF) | CSIC 100 (RAG ON) | CSIC 250 (RAG OFF) | CSIC 250 (RAG ON) |
|------|---------------------|--------------------|---------------------|--------------------|
| Precision | 1.000 | 1.000 | 1.000 | 1.000 |
| Recall | 0.440 | 0.440 | 0.404 | 0.404 |
| F1 | 0.611 | 0.611 | 0.575 | 0.575 |
| FPR | 0.000 | 0.000 | 0.000 | 0.000 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Valid | YES | YES | YES | YES |

与上次 (2026-05-04) 对比：Recall 提升 ~6pp (0.38→0.44 / 0.32→0.404)。

## 路由分布 (CSIC 250 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 93 |
| Fast-pass | 188 |
| Local LLM | 43 |
| React | 3 |
| Local Block | 83 |

## 主要发现

1. Recall 较上次有提升：bf0f4e1 新增的 pattern 起作用
2. RAG ON/OFF 指标仍无差异：RAG 在流水线中位置靠后
3. Fast-pass 仍是主要漏检来源

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
