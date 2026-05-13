# Tasks — Harden WAF2 Local Scorer

## 1. OpenSpec Artifacts

- [x] 1.1 proposal.md
- [x] 1.2 design.md
- [x] 1.3 specs delta under `specs/waf2-local-attack-scoring/spec.md`
- [x] 1.4 `openspec validate harden-waf2-local-scorer-probe-and-decode --strict` 通过

## 2. Baseline & 回归集

- [x] 2.1 复用 `waf2/rag/eval/runs/2026-05-10-big/` 作为 before 基线（已存在，不重跑）
- [x] 2.2 从 `waf2/rag/eval/failures.jsonl` 中过滤出 detectable FN，落盘为 `waf2/rag/eval/probe-fn-regression.jsonl`（含 method/path/body/期望 category）。脚本：`waf2/rag/scripts/build_probe_regression.py`。实际产出 35 条（dedupe 后）
- [x] 2.3 在 `waf2/rag/scripts/` 增加 `eval_probe_regression.py`：读上面 jsonl → 调反代 → 输出命中率

## 3. Probe 路径黑名单

- [x] 3.1 在 `waf2/local_attack_score.py` 增加 `LEGACY_PROBE_PATH_PREFIXES`（`/_vti_pvt`、`/_vti_bin`、`/_vti_cnf`、`/iisadmpwd/`、`/scripts/`、`/msadc/`、`/cgi-bin/printenv`）
- [x] 3.2 增加 `LEGACY_PROBE_SUFFIXES`（`.inc`、`.htr`、`.asa`、`.asax`、`.cmd`、`.bak`、`.old`、`.swp`，case-insensitive）
- [x] 3.3 增加 `LEGACY_PROBE_SUFFIX_WHITELIST` 空集
- [x] 3.4 `_legacy_probe_hits` 在 `score_request` 的 `unknown` 类别下短路打分 0.95
- [x] 3.5 单测：6 条（iisadm/htr、_vti_pvt、.INC 大小写、jsp 后追 .inc、白名单豁免、正常 .gif 不误报）

## 4. 双重 URL Decode

- [x] 4.1 在 `waf2/normalization.py` 暴露 `double_url_decode(s: str) -> str`
- [x] 4.2 增加 `has_residual_percent(s: str) -> bool`
- [x] 4.3 `_decode_text` 已经包含 2 层 URL decode，`analysis_text` 已包含 doubly-decoded text；新增 `alpha_boolean_tautology` SQLi 模式以兜住 `'OR'a='a` 一类；同时把 `quoted_boolean_tautology` 权重从 0.65 提到 0.88（同样高置信，过去停留在 gray-zone 因 LLM 放行漏报）
- [x] 4.4 `_multi_layer_encoding_hits` 检查 2 层解码后残留 `%XX`，加 0.15 弱分进入 gray-zone
- [x] 4.5 单测：4 条（双层 SQLi alpha、双层 SQLi quoted-numeric、双层 path traversal、三层残留只加弱分）

## 5. Header 打分

- [x] 5.1 新增 `score_headers(headers)` 覆盖 `Referer` / `Cookie` / `User-Agent`，复用 SQLi/XSS/path-traversal pattern
- [x] 5.2 新增 `SCANNER_UA_PATTERNS` (sqlmap/nikto/nessus/acunetix/wpscan/nmap scripting/w3af/havij)，命中给 0.4 分、`scanner_signature`
- [x] 5.3 在 `waf2/waf2_proxy.py` proxy 入口过滤三个 header 传入 `analyze_request`；cache key 包含 header md5 短哈希以避免缓存毒化
- [x] 5.4 单测：6 条（scanner UA、Referer SQLi、Cookie XSS、干净浏览器无误报、超长 header 安全截断、`score_request` 接受 headers）

## 6. 集成回归 — **需要用户运行**（依赖 Docker + Ollama）

- [x] 6.1 `eval_probe_regression --waf2 http://localhost:8081`: 35/35 (100%) direct_block ✅
- [x] 6.2 CSIC 100+100 RAG OFF (小样本快验): P=1.000 R=0.850 F1=0.919 FPR=0.000 ✅
- [x] 6.3 CSIC 100+100 RAG ON: 与 OFF 完全一致 (RagQ=5/RagHit=3/全部 gated)，0 FP ✅
- [x] 6.4 对抗集 40: F1=1.000 (OFF=ON)，30/30 攻击拦截，0/10 误拦 ✅
- [x] 6.5 `waf2/rag/eval/runs/2026-05-13-probe-decode/` README + results + failures + config/stats snapshot ✅
- [x] 6.6 CSIC 1000+1000 大样本验证：RAG OFF Recall=0.761 (+3.8 pp vs baseline 0.723)，F1=0.864 (+2.5 pp)；RAG ON Recall=0.762 (+3.9 pp)，F1=0.865；FPR=0 ✅

> 已离线验证：
> - 单测 37 条全过
> - probe-fn-regression.jsonl 35/35 (100%) 在 `normalize_request + score_request` 内联调用下 direct-block
> - 5000 条正常 CSIC 样本 0 FP（精度 1.000 不受影响）
> - 25,065 条 Anomalous CSIC 样本中本地 scorer 直接 block 72.6%（相比 baseline run 中 `static_block=640/1000` 的 64% 上限有 ~9 pp 提升空间）

## 7. Spec 同步

- [x] 7.1 完成 `specs/waf2-local-attack-scoring/spec.md` 中 ADDED Requirements（3 类：probe / double-decode / header）
- [ ] 7.2 在 PR 描述里给出 before/after 指标对比表（等 6.x 集成跑完）

## 8. 收尾

- [ ] 8.1 PR review
- [ ] 8.2 archive change to `openspec/changes/archive/`
- [ ] 8.3 sync delta 到 `openspec/specs/waf2/spec.md` 或保留在 capability spec（视项目惯例）
