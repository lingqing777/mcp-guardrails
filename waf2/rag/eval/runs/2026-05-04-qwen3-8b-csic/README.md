# Eval Run: qwen3:8b + CSIC 2026-05-04

## 环境

- Commit: `78e986e` (master: `bf0f4e1`)
- Model: `qwen3:8b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 100 | CSIC 250 |
|------|----------|----------|
| Precision (RAG OFF) | 1.000 | 1.000 |
| Recall (RAG OFF) | 0.380 | 0.320 |
| F1 (RAG OFF) | 0.551 | 0.485 |
| FPR (RAG OFF) | 0.000 | 0.000 |
| Precision (RAG ON) | 1.000 | 1.000 |
| Recall (RAG ON) | 0.380 | 0.320 |
| F1 (RAG ON) | 0.551 | 0.485 |
| FPR (RAG ON) | 0.000 | 0.000 |
| LLM Errors | 0 | 0 |
| Valid | YES | YES |

RAG ON/OFF 指标无差异。

## 路由分布 (CSIC 250 RAG OFF)

| 路由 | 数量 |
|------|------|
| Static Block | 74 |
| Fast-pass | 209 |
| Local LLM | 43 |
| React | 3 |
| Local Block | 64 |

## 主要发现

1. Recall 低：CSIC subtle mutation 攻击被 business fast-pass 放行
2. RAG fire 但不改变拦截结果：RAG 在流水线中位置靠后，被架空
3. Parse Failed 在 RAG ON 时增多：ReAct 路径输出格式不稳定

## 文件

- `results-csic-latest.md` — 最新评测报告（CSIC 250）
- `failures-csic-latest.jsonl` — 最新失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
