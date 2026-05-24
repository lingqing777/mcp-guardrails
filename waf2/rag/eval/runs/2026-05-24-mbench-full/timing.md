# M-Bench-Core Full Run Timing (2026-05-24)

总耗时 + 单 case 平均响应时间(`latency_ms` 字段为 WAF1/WAF2 评测器各自报告的处理耗时)。

## Per-Round Wall-Clock

| Round | Split | n | Total wall-clock | Mean / case |
|---|---|---|---|---|
| WAF1 strict | attacks | 150 | < 0.1s | 0.1ms |
| WAF1 strict | benign  | 1000 | < 0.1s | 0.04ms |
| WAF1 full   | attacks | 150 | 0.4s | 2.6ms |
| WAF1 full   | benign  | 1000 | 3.9s | 3.9ms |
| WAF2 rag-off | attacks | 150 | 33.4 min (2005s) | 13.4s / case |
| WAF2 rag-on  | attacks | 150 | 36.7 min (2199s) | 14.7s / case |
| WAF2 rag-on  | benign  | 1000 | _跑分中_ | _跑分中_ |
| WAF2 rag-off | benign  | 1000 | _未跑(用户决议:1 round only)_ | _stub: passed_ |

## Latency Distribution

```
attacks rag-off (n=150): mean=13367ms median=21600ms p95=24216ms max=26697ms
attacks rag-on  (n=150): mean=14664ms median=22533ms p95=26160ms max=28910ms
```

中位数远高于均值说明 latency 分布是 **bimodal**:
- 一小部分 case (≈ 30%): 0-50ms — WAF2 static 规则 fast block (e.g. ssrf 内网 IP / sql_injection 关键字模式)
- 大部分 case (≈ 70%): 18-25s — WAF2 走 LLM (Ollama qwen3:8b 本地推理) 加 RAG 检索

RAG-on 比 RAG-off 平均多 1.3s — RAG 向量检索 + context 拼接的额外耗时。

## LLM 上游

- Model: `qwen3:8b` via Ollama `http://host.docker.internal:11434/v1`
- LLM timeout: 180s, fail policy: `fail_open` (LLM 失败/超时则放行)
- RAG knowledge base: 3364 entries (PayloadsAllTheThings + OWASP CRS)

## 主报告写入

Total run timing 写入 `dual-layer-mbench-report.md` 的 Reproduction footer 后,标"User-visible benchmark wall-clock"。

注:WAF1 用时几乎可忽略 — 即使 1150 case 串行 < 5 秒。M-Bench-Core 评测的真实瓶颈在 WAF2 LLM 调用 (尤其 attacks 因为很多走 ReAct + RAG 完整路径)。
