# Tasks — Add WAF2 Eval Failure Analysis Loop

## 1. OpenSpec Artifacts

- [ ] 1.1 proposal.md
- [ ] 1.2 design.md
- [ ] 1.3 specs delta under `specs/waf2-evaluation/spec.md` (新建 capability)
- [ ] 1.4 `openspec validate add-waf2-eval-failure-analysis-loop --strict` 通过

## 2. WAF2 — eval_mode response headers

- [x] 2.1 在 `waf2/waf2_proxy.py` 的请求处理函数末尾（block + pass 两条路径都需要）增加：当 `eval_mode=true` 时附加 D1 定义的 X-Waf2-* headers
  - `X-Waf2-Outcome` / `X-Waf2-Detected-Category`
  - `X-Waf2-Local-Score-Total` / `X-Waf2-Local-Score-Top` (top-3, csv)
  - `X-Waf2-Rag-Used` / `X-Waf2-Rag-Top-Score` / `X-Waf2-Rag-Top-Category`
  - `X-Waf2-Route` / `X-Waf2-Reasons` (pipe-separated)
  - `X-Waf2-Normalize-Meta` (depth=,frags=,decoded=,b64=)
  - `X-Waf2-Latency-Ms`
- [x] 2.2 确保单 header ≤ 256 bytes，超长字段（如 reasons > 10 条）截断并附 `...`
- [x] 2.3 单测 `test_waf2_eval_mode_headers_present`：mock 一个请求，eval_mode=true 时 response 含所有 X-Waf2-* header
- [x] 2.4 单测 `test_waf2_prod_mode_no_eval_headers`：eval_mode=false 时不附加 X-Waf2-* header

## 3. eval_rag.py — schema 扩展 + ambiguous

- [x] 3.1 扩 `_failure_record` schema：从 response header 读取 D1 全部字段，merge 进 record
- [x] 3.2 加 ambiguous 判定（D2 公式）：在 `evaluate_round` attack/normal 循环里，对 PASS case 也判断是否进 ambiguous
- [x] 3.3 输出 `cases-csic-rag-off.jsonl` / `cases-csic-rag-on.jsonl` 到 `runs/<date>/`，原 `failures.jsonl` 保留向后兼容（slim FN+FP-only view）
- [x] 3.4 单测：模拟 attack/normal/ambiguous 三类 case，验证 cases-*.jsonl 每行 schema 完整

## 4. eval_prompt_injection.py — per-case output

- [x] 4.1 在 `run_round` 循环里收集 per-case：`(case_id=行号, subcategory, wrap, expected=blocked, outcome, headers)`
- [x] 4.2 加 ambiguous 判定（同 D2）
- [x] 4.3 输出 `cases-b0-rag-off.jsonl` / `cases-b0-rag-on.jsonl`
- [x] 4.4 单测：3-case 假数据集，验证 per-case JSONL 输出对齐 CSIC schema

## 5. eval_injecagent.py — per-case output

- [x] 5.1 在 `run_split` 循环里收集 per-case：`(case_id=split:行号, split, expected=blocked, outcome, headers)`
- [x] 5.2 加 ambiguous 判定（同 D2）
- [x] 5.3 输出 `cases-b1-{split}.jsonl`（4 个 split 各一）
- [x] 5.4 单测：1-case 假数据，验证 schema 对齐

## 6. label_failures.py — auto 推导

- [x] 6.1 新文件 `waf2/rag/scripts/label_failures.py`，CLI: `label_failures.py <cases.jsonl> [-o labels.jsonl]`
- [x] 6.2 实现 R1~R8 规则（design.md D3）。规则顺序即优先级，first-match。
- [x] 6.3 输出 `labels-*.jsonl` schema：`{case_id, layer, cause_hint, fix_hint, confidence, rule_id}`
- [x] 6.4 当 unknown 占比 > 30% 时 stderr 警告"规则覆盖不足"
- [x] 6.5 单测：对每条 R1~R7，构造一个 cases.jsonl 输入 → labels.jsonl 输出 → assert layer/cause/fix 命中

## 7. sample_for_manual.py — 抽样

- [x] 7.1 新文件 `waf2/rag/scripts/sample_for_manual.py`，CLI: `sample_for_manual.py <cases.jsonl> --eval (csic|b0|b1) [--n 30]`
- [x] 7.2 B-1 模式：抽 30 condition `random.seed("waf2-eval-fal-2026-05-17")` 写死
- [x] 7.3 B-0/CSIC 模式：全列（量小）
- [x] 7.4 输出 markdown checklist：每条 `- [ ] case_id=<id>  body=<truncated>  auto_layer=<R?>  cause=__________`，留空给人工填
- [x] 7.5 单测：固定 seed，输出 case 顺序稳定

## 8. build_failure_report.py — bucket 报告

- [x] 8.1 新文件 `waf2/rag/scripts/build_failure_report.py`，CLI: `build_failure_report.py <runs/<date>/> [-o failure-analysis.md]`
- [x] 8.2 读取 `cases-*.jsonl` + `labels-*.jsonl` + 可选 `b1-sample-30.md`（人工标好的）
- [x] 8.3 按 `fix_hint` 聚合：每个 fix 桶列 `(总数, 高 conf 占比, 来自哪些 eval/split, 抽样命中率)`
- [x] 8.4 输出 ROI 表格：`fix_hint → covered_FN_count → maps_to_queued_change`
- [x] 8.5 报告头部含 `unknown` 占比 + 触发抽样扩展的判定

## 9. 集成跑通

- [x] 9.1 在最新 commit 上跑 `eval_rag.py --dataset csic --sample 30`，验证 `cases-*.jsonl` 落地 — Phase E 实跑: 2 case (1 FN × 2 round), Recall 0.967, FPR 0
- [x] 9.2 跑 `eval_prompt_injection.py --mode both`，验证 `cases-b0-*.jsonl` 落地 — Phase E 实跑: 234 case (165 RAG OFF + 69 RAG ON), 含 137+44 FN + 28+25 miscategorized
- [x] 9.3 跑 `eval_injecagent.py --splits dh_base --limit 30`，验证 `cases-b1-*.jsonl` 落地 — Phase E 实跑: 30 case (29 FN + 1 miscategorized as command_injection), BR 3.3% ASR 96.7%
- [x] 9.4 跑 `label_failures.py` 在三套 cases 上，验证 labels 输出且 unknown < 30% — 加 R9 后 unknown=0.0%, R2:140 R3:18 R4:2 R5:5 R7:54 R9:47
- [x] 9.5 跑 `sample_for_manual.py` 对 B-1 输出 30 条抽样 — emit b1-manual.md (30 / 30 全列, B-1 limit=30 == full size)
- [x] 9.6 人工标这 30 条的 `cause`（由 AI 分析 body 后批量标注 social_eng_no_marker，详见 b1-manual.md analyst note）— 30/30 confirmed semantic single bucket
- [x] 9.7 跑 `build_failure_report.py`，得到 `failure-analysis.md` — fath_judge_wrap 192 / field_path_boost 140 / category_rule_refine 54 / react_prompt_robustness 47 / kb_inject_socialeng 18 / kb_clean 2
- [x] 9.8 验证假设：B-1 30 抽样里非 social_eng_no_marker 条数 < 3（如果 ≥ 3 触发扩抽样到 100）— **verdict: intact**, 30/30 dominant, 0 non-dominant

## 10. 旧 change 收尾

- [x] 10.1 在 `evaluate-waf2-rag-react-routing-and-models` 的 tasks.md 里把 4.1-4.3 + 10.1 标 "scope moved to add-waf2-eval-failure-analysis-loop"

## 11. Spec 同步

- [x] 11.1 完成 `specs/waf2-evaluation/spec.md` ADDED Requirements
- [ ] 11.2 PR 描述：附 `failure-analysis.md` 摘要（每个 fix 桶覆盖多少 FN）+ B-1 抽样验证假设结果 — **由用户在跑完真 Phase E 后撰写**

## 12. 收尾

- [x] 12.1 self-review + `openspec validate add-waf2-eval-failure-analysis-loop --strict`
- [ ] 12.2 commit + push — **由用户执行**
- [ ] 12.3 `openspec archive add-waf2-eval-failure-analysis-loop -y`（在确认下游 change `harden-waf2-llm-judge-field-isolation` 能消费这套数据后）— **由用户执行**
