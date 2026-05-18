# Tasks — Harden WAF2 ReAct Fallback with RAG Rescue

## 1. OpenSpec Artifacts

- [ ] 1.1 proposal.md
- [ ] 1.2 design.md
- [ ] 1.3 specs delta under `specs/waf2-rag-enforcement/spec.md` (新建 capability)
- [ ] 1.4 `openspec validate harden-waf2-react-fallback-rag-rescue --strict` 通过

## 2. WAF2 — Config 字段

- [ ] 2.1 `Config` 类（waf2_proxy.py）增 3 字段：
  - `rag_decisive_fallback_enabled: bool = True`
  - `rag_decisive_fallback_min_score: float = 0.55`
  - `rag_decisive_fallback_categories: set[str] = {"prompt_injection"}`
- [ ] 2.2 `/waf2/config` PATCH 接受这 3 个字段的更新，类型校验
- [ ] 2.3 `cache_dims` 字符串增 `rag_rescue={int(config.rag_decisive_fallback_enabled)}` 维度，避免开关切换后命中 stale cache

## 3. WAF2 — rescue helper

- [ ] 3.1 新增 `_rag_decisive_rescue(rag_meta: Dict, local_meta: Dict, direction: str) -> Optional[Dict]`，签名与 design D1 一致
- [ ] 3.2 函数仅在 `config.rag_decisive_fallback_enabled` 时进入主体，否则立即返回 None
- [ ] 3.3 校验 `rag_meta` shape：dict + `rag_used=True` + `rag_top_score` 是数值
- [ ] 3.4 实现双源 category 选取 helper `_rescue_category(rag_meta, local_meta)`（D2）：
  - RAG cat 在白名单 → 用 RAG cat
  - 否则 local_top_category 在白名单 AND `local_top_score >= 0.35` → 用 local cat
  - 都不满足 → return None
- [ ] 3.5 输出 dict 含完整 detection_result 字段：`blocked / direction / category / reason / engine / route / route_reasons`，`route_reasons` 含 `rag_cat` 或 `local_cat` 标记（取决于 category 来源）

## 4. WAF2 — 接入 fallback 分支

- [ ] 4.1 `agent_analyze_request`: 当 `run_react_agent` 返回 None，先调 `_rag_decisive_rescue(rag_meta, local_meta, 'request')`，命中即 return；`local_meta` 从已有的 `score_result` 取 `top_category` + `top_score`
- [ ] 4.2 `agent_analyze_response`: 同样接入（response 无 local_meta 来源时传 `{}`，等同 RAG 单源退化）
- [ ] 4.3 stats 增计数器 `react_fallback_rag_rescued`，每次救援触发 +1；区分 `rescued_via_rag_cat` / `rescued_via_local_cat` 两个子计数

## 5. eval_headers.py — X-Waf2-Route 新值

- [ ] 5.1 `KNOWN_ROUTES` 集合添加 `react_fallback_rag_rescue`
- [ ] 5.2 救援触发时 `X-Waf2-Reasons` 含 `rag_decisive_fallback` token

## 6. label_failures.py — R10 规则

- [ ] 6.1 新增 `rule_R10_react_rescued(case)`：`outcome=blocked AND route=react_fallback_rag_rescue`
- [ ] 6.2 priority 顺序更新为：R7 → R10 → R1 → R5 → R9 → R4 → R6 → R3 → R2 → R8
- [ ] 6.3 unknown 占比警告阈值不变（30%）

## 7. build_failure_report.py — 桶映射

- [ ] 7.1 `FIX_TO_CHANGE` 加 `(none, monitored): "harden-waf2-react-fallback-rag-rescue (this)"` 条目
- [ ] 7.2 报告头部新增 "rescued by current change" 统计行：`R10 count` / 占原 R9 比例

## 8. 单测

- [ ] 8.1 `test_rag_decisive_rescue.py` 新文件（不动原有测试，仅追加新文件）
  - rescue 触发 (RAG cat 在白名单): rag_used=True + score=0.60 + rag_cat=PI → blocked, category=PI, route_reasons 含 `rag_cat`
  - rescue 触发 (local cat 兜底): rag_score=0.58 + rag_cat=sql_i + local_cat=PI + local_score=0.55 → blocked, category=PI, route_reasons 含 `local_cat`
  - rescue 跳过 (低 RAG 分): score=0.40 → None
  - rescue 跳过 (RAG cat + local cat 都不在白名单): rag_cat=sql_i + local_cat=command_i → None
  - rescue 跳过 (RAG cat 不在 + local score 太低): rag_cat=sql_i + local_cat=PI + local_score=0.20 → None
  - rescue 跳过 (rag_used=False): → None
  - rescue 跳过 (开关 off): config.rag_decisive_fallback_enabled=False → None
  - 救援结果包含正确的 route / reasons / category / engine 字段
- [ ] 8.2 `test_label_failures.py` **末尾追加**（不动现有 36 个测试）：
  - R10 fires: outcome=blocked + route=react_fallback_rag_rescue → R10
  - R10 vs R7 priority: record_kind=miscategorized + route=react_fallback_rag_rescue → R7 优先（miscat 是 record_kind 维度，更基础）
  - main 块 tests 元组追加这 2 个测试函数
- [ ] 8.3 `test_local_pipeline.py` 中 X-Waf2 header 测试增 1 条：route=react_fallback_rag_rescue 时 header 正确序列化

## 9. 集成跑通

- [ ] 9.1 build + restart waf2 docker，确认无 ModuleNotFoundError
- [ ] 9.2 跑 `eval_prompt_injection.py --mode rag-on --limit 30`（B-0 sample 30，关注关键 case 复现）：
  - sample 30 应包含至少几个原 R9 case（race-on:83、85、其他 indirect-PI 中文 carrier）
  - cases-b0-rag-on.jsonl 中 `route=react_fallback_rag_rescue` 出现 ≥ 1 次
  - 触发救援的 case 必须 outcome=blocked 且 category=prompt_injection
  - 关键验收：原 R9 中 indirect-PI 中文 carrier case 应被救回（如 b0:rag-on:83、85）
- [ ] 9.3 跑 `eval_rag.py --dataset csic --sample 100`（CSIC 100 RAG-ON）：
  - FPR ≤ 0.005（normal 50 上 ≤ 0 FP）
  - Precision = 1.000
  - Recall ≥ 0.85（不破 CSIC 100 baseline）
- [ ] 9.4 跑 `label_failures.py` on 新 cases-b0-rag-on.jsonl
  - R10 count ≥ 1
  - unknown 占比 < 5%
- [ ] 9.5 跑 `build_failure_report.py runs/<date>/`
  - 报告头部"rescued by current change" 行非空
  - fix_hint 表里 `(none, monitored)` 桶 count 与 R10 count 一致

## 10. 验收数据归档

- [ ] 10.1 runs/<date>-react-fallback-rag-rescue/ 含：
  - cases-b0-rag-on.jsonl, labels-b0-rag-on.jsonl
  - cases-csic-rag-{off,on}.jsonl, labels-*.jsonl
  - b0-report.json, csic-100-report.json
  - failure-analysis.md
  - README.md（记 BR-before / BR-after / FPR、saved-FN 数）

## 11. Spec 同步

- [ ] 11.1 完成 `specs/waf2-rag-enforcement/spec.md` ADDED Requirements
- [ ] 11.2 PR 描述：贴 BR 提升 + FPR 守住 0 + 救援 case 抽样 3 条 — **由用户在跑完 Phase 9 后撰写**

## 12. 收尾

- [ ] 12.1 self-review + `openspec validate harden-waf2-react-fallback-rag-rescue --strict`
- [ ] 12.2 commit + push — **由用户执行**
- [ ] 12.3 `openspec archive harden-waf2-react-fallback-rag-rescue -y` — **由用户执行，在确认数据归档完成后**
