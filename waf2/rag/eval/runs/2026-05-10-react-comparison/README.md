# Eval Run: ReAct OFF/ON 对照 2026-05-10

## 环境

- Commit: `727c663`
- Model: `qwen3:8b` (Ollama local)
- Base URL: `http://host.docker.internal:11434/v1`
- Provider: local / ollama
- RAG: enabled (3364 entries, threshold=0.60)
- 数据集: CSIC 2010 (250 samples) + Adversarial (40 samples)

## 对抗集结果

| 指标 | RAG OFF | RAG ON |
|------|---------|--------|
| Precision | 1.000 | 1.000 |
| Recall | 1.000 | 1.000 |
| F1 | 1.000 | 1.000 |
| FPR | 0.000 | 0.000 |
| CategoryAcc | 0.833 | 0.833 |

对抗集 30/30 全部拦截，0/10 良性误报。所有攻击在 RAG 前被前置层判定。

## CSIC 250 ReAct OFF/ON 对照

| 指标 | ReAct OFF (RAG OFF) | ReAct OFF (RAG ON) | ReAct ON (RAG OFF) | ReAct ON (RAG ON) |
|------|---------------------|--------------------|---------------------|--------------------|
| Precision | 1.000 | 1.000 | 1.000 | 1.000 |
| Recall | 0.788 | 0.788 | 0.788 | 0.788 |
| F1 | 0.881 | 0.881 | 0.881 | 0.881 |
| FPR | 0.000 | 0.000 | 0.000 | 0.000 |
| LLM Errors | 0 | 0 | 0 | 0 |
| Valid | YES | YES | YES | YES |
| React routes | 0 | 0 | 2 | 2 |
| ParseFail | 3 | 3 | 3 | 2 |

## 结论

- ReAct ON 仅触发 2 个 React 路由（CSIC 样本中大部分被 static/fast-pass 拦截）
- ReAct OFF/ON 对 Recall、Precision、F1 无差异
- RAG ON/OFF 对指标无差异
- CSIC 数据集不适合评估 ReAct 路径，需要更复杂的对抗样本

## 文件

- `results-react-off.md` — ReAct OFF 评测报告
- `results-react-on.md` — ReAct ON 评测报告
- `failures-react-off.jsonl` — ReAct OFF 失败样本
- `failures-react-on.jsonl` — ReAct ON 失败样本
- `waf2-config.json` — WAF2 运行时配置快照
- `waf2-stats.json` — WAF2 请求统计快照
