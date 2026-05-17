# Add WAF2 Eval Failure Analysis Loop

## Why

`harden-waf2-nested-json-extraction` 已 ship 后，B-0 / B-1 / CSIC 三套 eval 出现两个"为什么没改进"的现象但**缺结构化数据**支持归因：

- B-1 InjecAgent BR 5.0% → 5.0%（持平），独立验证 nested 提取生效、attacker text reach analysis_text，但 LLM 仍 PASS。诊断只能靠 stderr 日志逐条肉眼看。
- B-0 `context_manip / response` 14.3% / 50.0% < 目标 50% / 75%，root cause 假设是 "LLM 把 untrusted 字段当 trusted"，但 25 条 FN 里到底有几条命中这个假设？没有数据答。

具体缺什么：

1. **eval 脚本不一致** — `eval_rag.py` (CSIC) 落地 `failures.jsonl`，但 `eval_prompt_injection.py` (B-0) 和 `eval_injecagent.py` (B-1) **只输出聚合**，每个 case 的 outcome / category / reasons / scores / route 不留痕。
2. **per-case 数据缺 "为什么" 字段** — 即便是 CSIC 的 `failures.jsonl`，schema 只有 `{kind, method, path, body, status, category, reason}`。FN 时 `category` / `reason` 是空的（WAF2 返回 200 不带这俩）。`local_score_breakdown` / `rag_top_score` / `route` 这些诊断信号完全没透出来。
3. **没有失败归类标签** — 即便有 per-case 数据，也没有把每条 FN 标到 "哪一层失守 / 什么 cause / 哪个 queued change 该修它" 这种 bucket，做不了"下一个 change 的 ROI 估算"。

结果：每次 ship 一个 hardening change，验收变成"看聚合 BR 升了多少"，看不到"我到底解了哪一类失败、新出现的 FN 是不是同一类"。

## What Changes

1. **WAF2 在 `eval_mode=true` 时附加 `X-Waf2-*` response headers**，把 `local_score_total` / `local_score_breakdown` / `rag_used` / `rag_top_score` / `rag_top_category` / `route` / `reasons` / `normalize_meta` / `latency_ms` 透传给 eval 脚本。生产模式不变。
2. **eval_rag.py 扩 `_failure_record` schema** — 消费上面的 header 字段，并加 `ambiguous` 判定（`outcome=passed` 且 `local_score >= 0.40` 或 `rag_top_score >= 0.55`）。FN + FP + ambiguous 全记到 `cases-*.jsonl`，原 `failures.jsonl` 保留向后兼容。
3. **eval_prompt_injection.py / eval_injecagent.py 加 per-case JSONL 输出**，与 CSIC 同 schema。
4. **新脚本 `label_failures.py`** — auto 推导 7 条规则（R1 normalize_miss / R2 local_score_low / R3 rag_miss / R4 rag_wrong / R5 llm_overrode / R6 router_too_loose / R7 miscategorized）+ R8 fallback=unknown 进抽样队列。输出 `labels-*.jsonl`。
5. **新脚本 `sample_for_manual.py`** — B-1 抽 30 case 验证 single-bucket 假设、B-0/CSIC FN 全列。输出 markdown checklist 等人工填 `cause` + `confidence`。
6. **新脚本 `build_failure_report.py`** — 聚合 labels，按 `hypothesized_fix` 分桶（`fath_judge_wrap` / `kb_inject_socialeng` / `field_path_boost` / 等），输出 `failure-analysis.md` 报告含 ROI 估算（每个 fix 桶覆盖多少 FN）。
7. **标记 `evaluate-waf2-rag-react-routing-and-models` 的 tasks 4.1-4.3 + 10.1** 为 "scope moved to add-waf2-eval-failure-analysis-loop"。

## Capabilities

### Added Capabilities

- `waf2-evaluation`: 新建 capability，覆盖 per-case 数据落地 schema、auto-推导规则、抽样策略、bucket → ROI 报告。

## Impact

- **Affected WAF2 code:**
  - `waf2/waf2_proxy.py`: eval_mode 分支增加 X-Waf2-* response headers（~10 行）
- **Affected eval code:**
  - `waf2/rag/scripts/eval_rag.py`: 扩 `_failure_record` schema、加 ambiguous 判定
  - `waf2/rag/scripts/eval_prompt_injection.py`: 加 per-case JSONL 输出
  - `waf2/rag/scripts/eval_injecagent.py`: 加 per-case JSONL 输出
  - `waf2/rag/scripts/label_failures.py`: 新文件
  - `waf2/rag/scripts/sample_for_manual.py`: 新文件
  - `waf2/rag/scripts/build_failure_report.py`: 新文件
- **不动**:
  - 任何 WAF2 拦截规则、KB 内容、LLM prompt、ReAct 路由阈值（这些是 loop 的消费者，不是它的生产者）
  - 生产模式行为（X-Waf2-* header 只在 eval_mode=true 时附加）
- **风险**:
  - X-Waf2-* header 长度上限：每条 ≤ 256 bytes（标准 HTTP 限制），`local_score_breakdown` / `rag_top_text` 会被截断成 top-3。非诊断盲点（要全量字段时直接看 stderr 日志）。
  - Auto-推导规则可能不全 — 用 R8 unknown fallback 兜底，触发人工抽样扩展。当 unknown 占比 > 30% 时报警。
  - B-1 抽样 30 个不足以推翻 single-bucket 假设：定义 "≥ 3 条非 social_eng_no_marker" 触发扩抽样到 100。
- **不在范围内**:
  - 修任何 FN（这是 loop 的下游消费）
  - 改 RAG KB / LLM prompt / 路由阈值
  - 引入新 eval dataset（沿用现有 CSIC / B-0 / B-1）
  - Dashboard 集成（per-case 数据只在 eval 流水线消费）
