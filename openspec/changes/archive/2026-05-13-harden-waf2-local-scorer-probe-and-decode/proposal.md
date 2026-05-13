# Harden WAF2 Local Scorer — Probe Paths & Double Decode

## Why

CSIC 1000+1000 评测（`waf2/rag/eval/runs/2026-05-10-big/`，qwen3:8b + full local-first 栈）显示：

- Precision = 1.000，FPR = 0.000 —— 没有误报问题
- **Recall = 0.723，277 个 false negative —— 这是当前真正的瓶颈**

将 277 个 FN 全量解码后聚类，结果如下：

- **39 条（14%）解码后存在可被规则稳定识别的强攻击信号**，但本地 scorer 漏过。这部分集中在三类：
  1. 老式 IIS / FrontPage / CGI 探测路径（`/_vti_pvt/`、`/iisadmpwd/*.htr`、`*.inc`、`*.asa`、`*.cmd` 等），CSIC 里高频出现，业务里 100% 不会用
  2. 经过**双重 URL 编码**的 SQLi（如 body 字段中 `dni=%27OR%27a%3D%27a`，header 中 `remember=on%22+AND+%221%22%3D%221`）—— 当前 normalization 只解码一次
  3. `Referer` / `Cookie` / `User-Agent` 三个 header 携带的 SQLi/XSS payload —— 当前 scorer 完全不打分 header
- 剩余 238 条（86%）解码后没有任何可识别攻击特征，属于 CSIC2010 已知的标注噪声，不在本 change 范围

修这 39 条预计 Recall 从 0.723 提升到 ≈0.76（+3-4 pp），且：

- 不新增 LLM 调用 —— probe 命中直接走 `static_block` 路由
- 几乎零延迟开销 —— 单次 URL decode < 0.1ms
- 零 FP 风险 —— pattern 都是高 precision 黑名单（业务里出现概率为 0）

## What Changes

1. 在 `waf2/local_attack_score.py` 引入 **legacy probe path 黑名单**（前缀 + 后缀两组），命中给 ≥ `local_score_block_threshold` 的分数，让 risk router 直接 `static_block`。
2. 在 `waf2/normalization.py` 暴露 `double_url_decode`，并在 `score_request()` 内对 path / query / body 用二次解码结果再过一次现有的 SQLi / XSS / path-traversal pattern。
3. 在 `local_attack_score.py` 新增 `score_headers(headers)`，把 `Referer` / `Cookie` / `User-Agent` 解码后纳入打分；同时对 `User-Agent` 检查 scanner 签名（sqlmap / nikto / nessus / acunetix）。
4. 增加针对性的回归集 `waf2/rag/eval/probe-fn-regression.jsonl`（从当前 39 个 detectable FN 抽取），作为新增 pattern 的最小验收依据。
5. 在 `waf2-local-attack-scoring` capability 下扩展 spec：增加三类 Requirements（probe 路径、双重 decode、header 打分）和对应 Scenarios。

## Capabilities

### Modified Capabilities

- `waf2-local-attack-scoring`: 增加 legacy web 探测路径打分、双重 URL decode、header 注入打分三类 Requirements

## Impact

- Affected WAF2 code:
  - `waf2/local_attack_score.py`: 新增 `LEGACY_PROBE_PATH_PATTERNS`、`SCANNER_UA_PATTERNS`、`score_headers()`、短路检查
  - `waf2/normalization.py`: 暴露 `double_url_decode` helper（若未实现）
  - `waf2/waf2_proxy.py`: 在调用 `score_request` 处传入 headers
  - `waf2/tests/test_local_pipeline.py`: 新增 probe / double-decode / header injection 单测
- 评测:
  - `waf2/rag/eval/probe-fn-regression.jsonl`: 新增定向回归集
  - `waf2/rag/eval/runs/<dated>-probe-decode/`: 新增 before/after run
- 配置: **不新增 config 字段**。probe pattern 是常量规则，不是策略；用户不需要调。
- 风险:
  - 若上游真的对外提供 `.inc` / `.bak` 静态资源，会被误杀。缓解：复用现有 `ENDPOINT_PARAM_SCHEMAS` 白名单思路，让业务路径可豁免后缀规则
  - 双重解码增加每请求一次字符串处理，预算 < 0.5ms / req，cache hit 路径不受影响
- 不在范围内:
  - RAG 是否要保留（另一个 change）
  - 评测集换血到 MCP 真实威胁模型（另一个 change）
  - ReAct 路由阈值调整
