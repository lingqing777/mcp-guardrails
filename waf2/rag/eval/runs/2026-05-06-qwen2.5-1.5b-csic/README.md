# Eval Run: qwen2.5:1.5b + CSIC 2026-05-06

## 环境

- Commit: `aa8ce3e`
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

与 qwen3:8b (aa8ce3e) 对比：指标完全一致，1.5b 小模型表现不逊于 8b。

## 路由分布 (CSIC 250 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 142 |
| Fast-pass | 146 |
| Local LLM | 31 |
| React | 3 |
| Local Block | 132 |

## 主要发现

1. qwen2.5:1.5b 与 qwen3:8b 在 CSIC 上指标一致，小模型足够胜任
2. aa8ce3e 的 endpoint parameter name mutations 是 Recall 提升的关键
3. RAG ON/OFF 仍无差异

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
