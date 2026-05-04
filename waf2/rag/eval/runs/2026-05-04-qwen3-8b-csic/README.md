# Eval Run: qwen3:8b + CSIC 2026-05-04

## 环境

- Commit: `e5f9676`
- Model: `qwen3:8b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010

## 结果汇总

| 指标 | CSIC 100 | CSIC 250 |
|------|----------|----------|
| Precision | 1.000 | 1.000 |
| Recall | 0.380 | 0.320 |
| F1 | 0.551 | 0.485 |
| FPR | 0.000 | 0.000 |
| LLM Errors | 0 | 0 |
| Valid | YES | YES |

RAG ON/OFF 指标无差异。

## 主要发现

1. Recall 低：CSIC subtle mutation 攻击被 business fast-pass 放行
2. RAG fire 但不改变拦截结果：RAG 在流水线中位置靠后，被架空
3. Parse Failed 在 RAG ON 时增多：ReAct 路径输出格式不稳定

## 文件

- `results-csic-100.md` — CSIC 100 评测报告
- `results-csic-250.md` — CSIC 250 评测报告
- `failures-csic-100.jsonl` — CSIC 100 失败样本
- `failures-csic-250.jsonl` — CSIC 250 失败样本
