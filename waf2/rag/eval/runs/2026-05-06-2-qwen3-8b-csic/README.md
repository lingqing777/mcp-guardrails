# Eval Run: qwen3:8b + CSIC 2026-05-06 (v2)

## 环境

- Commit: `aa8ce3e`
- Model: `qwen3:8b` (Ollama local)
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

与上次 (aa8ce3e vs bf0f4e1) 对比：Recall 大幅提升 (+26pp / +24pp)。

## 路由分布 (CSIC 250 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 146 |
| Fast-pass | 146 |
| Local LLM | 31 |
| React | 3 |
| Local Block | 136 |

## 主要发现

1. aa8ce3e 的 endpoint parameter name mutations 效果显著，Recall 从 0.44 提升到 0.70
2. Fast-pass 数量从 188 降至 146，更多攻击被 static block 拦截
3. RAG ON/OFF 仍无差异，RAG 流水线位置问题未解决

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
