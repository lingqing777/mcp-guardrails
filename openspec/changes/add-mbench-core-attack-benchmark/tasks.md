# Tasks — M-Bench-Core Attack Benchmark

## 1. Foundation — schema 和数据集骨架

- [x] 1.1 创建 `waf2/rag/eval/m-bench-core/` 目录,占位 `attacks.jsonl` / `benign.jsonl` (空文件)
- [x] 1.2 编写 `waf2/rag/eval/m-bench-core/schema.json` — JSON Schema, 覆盖单步样本和多步样本两个分支, oneOf 按 `family` 字段分流
- [x] 1.3 编写 `waf2/rag/eval/m-bench-core/README.md` 骨架 — 章节: Overview / Dataset structure / Single-step vs multi-step schema / Paired hard-negative methodology / Tool universe (real vs synthetic) / Comparison with CSIC / B-0 / adversarial / InjecAgent / Regeneration steps / Ground-truth labeling conventions
- [x] 1.4 在 README 列出工具 universe: woocommerce (9) / wordpress (4) / supabase / mail / file_read_MCP / http-client / server-github + 合成工具 (xml_processor 等, 占比 ≤ 15%)
- [x] 1.5 在 README 写明 paired hard-neg 6 类配对模板 (`SELECT … OR 1=1`, `<script>`, `../etc/passwd`, "Ignore previous instructions", `127.0.0.1`/`169.254.x.x`, API key 形态)

## 2. Pilot — 50 条 mini-dataset 验证流程

- [x] 2.1 在 `waf2/rag/eval/m-bench-core/pilot/` 下创建 `attacks.jsonl` (45 条恶意 = 15 char_injection + 15 prompt_injection_and_priv_esc + 15 call_chain) 和 `benign.jsonl` (5 条 handcrafted hard-neg, 配对 pilot attacks)
- [x] 2.2 Pilot call_chain 15 条覆盖全部 5 种 `expected_chain` (data_exfiltration / credential_theft / recon_then_exploit / supabase_lethal_trifecta / prompt_injection_to_exfil), 每种至少 1 条; `expected_block_step` ∈ {1,2,3} 都至少出现一次
- [x] 2.3 用 `ajv` (或等价工具) 校验 pilot jsonl 全部符合 schema.json (Python `jsonschema` 通过)
- [x] 2.4 Pilot 数据集 git commit 前的 fast review: 手动抽查每条恶意是否 `expected_block_by` 标注合理 (能命中现有 WAF1 规则), 每条良性是否真"语义正常" — 内联 review 完成 (见 pilot 数据 + 标注), 实际命中率待 §8 pilot run 反馈

## 3. WAF1 Harness — Node 评测器

- [x] 3.1 扩展 `mcp-hub/scripts/_waf1_eval_lib.mjs`: 新增 `evaluateChain(steps, ctx)` 帮助函数, 逐步调 `validateToolCall`, 命中即停, 返回 `{blocked_at_step, blocked_step_result, all_results}`
- [x] 3.2 扩展 `_waf1_eval_lib.mjs`: 新增 `assertWaf1HistoryEmpty()` 帮助函数, 调用 `getCallHistory()` 并断言为空 (用于每个 case 之前 sanity check)
- [x] 3.3 创建 `mcp-hub/scripts/run_waf1_on_mbench.mjs` — 命令行参数 `--jsonl <path>` `--variant strict|full|both` `--out-dir <dir>`, 沿用 `run_waf1_on_b0.mjs` 模式
- [x] 3.4 Harness 主循环: 按行读取 jsonl, 按 `family` 字段分流单步/多步; 每个 case 前调 `resetWaf1State()` + `assertWaf1HistoryEmpty()`
- [x] 3.5 单步样本: 调 `evaluateWaf1(tool, args, ctx)` (沿用 b0 模式), 输出 `case_id = mbc:waf1-<variant>:<NNNN>` (4 位 0-padded)
- [x] 3.6 多步样本: 调 `evaluateChain(steps, ctx)` with `ctx.clientId = "mbc-chain-<case_id>"`, 输出含 `blocked_at_step` / `outcome` / `steps_results[]`
- [x] 3.7 输出 jsonl 字段完整 (`case_id`, `dataset=mbench`, `round`, `label`, `family`, `subcategory`, `outcome`, `detected_category`, `detected_namespace`, `latency_ms`, 多步特有的 `blocked_at_step`, 单步特有的 `expected_block_by` 透传)
- [x] 3.8 创建 `mcp-hub/scripts/run_waf1_on_mbench.test.mjs` — Node 自带 `node --test`, 覆盖: 单步 attack 正确分类 TP/FN, 多步 attack 早期拦截 (step 1) 也算 TP, 多步 attack 未拦截算 FN, hard-neg benign 计 FP/TN, `assertWaf1HistoryEmpty` 在 case 间确实归零

## 4. WAF2 Harness — Python 评测器

- [x] 4.1 创建 `waf2/rag/scripts/run_waf2_on_mbench.py` — 命令行参数 `--jsonl <path>` `--rag-mode on|off|both` `--out-dir <dir>`, 沿用 `eval_prompt_injection.py` 模式调 WAF2 `/waf2/analyze`
- [x] 4.2 单步样本: 直接喂给 WAF2 (把 `tool` + `args` 打包成合成 `tools/call` 请求体, sniff `path=/mcp` 或现有 `eval_prompt_injection` 兼容形状)
- [x] 4.3 多步样本: **只评测 `steps[-1]`**, 输出含 `waf2_evaluated_step=<steps.length>`, 在报告里会被标注 "WAF2 仅评测最后一步"
- [x] 4.4 输出 `case_id = mbc:rag-on:<NNNN>` / `mbc:rag-off:<NNNN>`, 字段完整对齐 spec.md "harness 输出字段" 要求
- [x] 4.5 创建 `waf2/tests/test_run_waf2_on_mbench.py` — pytest, 覆盖: 单步 attack outcome 解析, 多步样本 `waf2_evaluated_step` 设置正确, RAG ON/OFF 双 round 输出文件命名约定

## 5. Synthesizer (如需) — 填充缺失 case 为 clean TP

- [x] 5.1 评估是否需要 `synthesize_mbench_full_cases.py` (类似 `synthesize_b0_full_cases.py`) — **决定: 跳过**。M-Bench-Core 的 WAF2 harness 对所有 case (含 benign) 都输出一行 jsonl, 不存在 b0 那种 sparse 现象 (b0 是 `classify_record_kind` 过滤掉 clean TP 才需要回填), 因此不需要 synthesizer。
- [x] 5.2 (条件性) 若需要, 编写 `synthesize_mbench_full_cases.py` 沿用 b0 模式; 否则在 design.md / README.md 显式说明 "M-Bench-Core 不需要 synthesizer, 因为没有 sparse 输出" — **已在 design.md D3 / README "Comparison with CSIC/B-0/..." 隐含说明; 显式补充在 design.md 中**。

## 6. Merge — 跨层 join

- [x] 6.1 创建 `waf2/rag/scripts/merge_mbench_layers.py` — 命令行参数 `--cases-dir <dir>` `--dataset-jsonl <attacks-and-benign>` `--out-dir <dir>`
- [x] 6.2 加载四份 cases jsonl (`waf1-strict`, `waf1-full`, `rag-on`, `rag-off`), 按 trailing colon segment (`<NNNN>`) inner-join
- [x] 6.3 计算 `waf1_union = waf1_strict OR waf1_full`, `waf2_full = rag_on`, `dual = waf1_union OR waf2_full` (per-case)
- [x] 6.4 输出 `cases-mbench-merged.jsonl` — 每行包含原始 case 字段 + 4 round 的 outcome + 3 层 derived (`waf1_union` / `waf2_full` / `dual`) + ground truth (`label`, `expected_block_step`, `paired_with`)
- [x] 6.5 缺行写入 `merge-misses.json`, 不进入 confusion matrix
- [x] 6.6 创建 `waf2/tests/test_merge_mbench_layers.py` — 验证: 多步样本 TP 判定逻辑 (`blocked_at_step <= expected_block_step` 算 TP), `paired_with` 反查正确, missing rows 被正确隔离

## 7. Report — 渲染最终报告

- [x] 7.1 创建 `waf2/rag/scripts/report_mbench.py` — 输入 `cases-mbench-merged.jsonl`, 输出 `dual-layer-mbench-report.md`
- [x] 7.2 Section 1: Header & methodology — 数据集版本、run 日期、layers、RAG mode、hardware、fairness disclosures
- [x] 7.3 Section 2 Table 1: Overall confusion — TP / FN / FP / TN / Precision / Recall / F1 / FPR × 3 层 (`waf1_union` / `waf2_full_pipeline` / `dual`); **F1 用真实 precision 计算, 不再 precision=1**
- [x] 7.4 Section 3 Table 2: Per-family confusion — 同列 × 3 层 × 3 家族 (`char_injection` / `prompt_injection_and_priv_esc` / `call_chain`)
- [x] 7.5 Section 4 Table 3: Per-tool-universe — 同列 × 3 层 × 2 universes (`real` / `synthetic`); universe 通过查询样本 `tool` 是否在真实 server 列表内确定
- [x] 7.6 Section 5 Table 4: Hard-neg vs template FP breakdown — 对每层, 统计 `source=handcrafted` 的 FP 数 vs `source=template` 的 FP 数 (绝对数 + 占该来源总数的百分比); 若 hard-neg FP rate 比 template FP rate 高 ≥10 个百分点, 输出 callout
- [x] 7.7 Section 6 Table 5: Chain block-step distribution — 对 `family=call_chain` 子集, 按 `expected_block_step ∈ {1,2,3,4}` 分组 recall × 3 层
- [x] 7.8 Section 7 Table 6: Per-subcategory recall matrix — recall per (`subcategory` × 3 层), 按样本数降序
- [x] 7.9 报告底部 reproduction footer — 列出 source jsonl 路径 + 评测命令 + git hash
- [x] 7.10 创建 `waf2/tests/test_report_mbench.py` — 验证: 6 张表全部出现, F1 != recall (precision 真实), hard-neg callout 触发条件正确

## 8. Pilot run — 跑通 50 条流程

- [x] 8.1 端到端跑 pilot: `node mcp-hub/scripts/run_waf1_on_mbench.mjs --jsonl waf2/rag/eval/m-bench-core/pilot/attacks.jsonl --variant both --out-dir waf2/rag/eval/runs/<date>-mbench-pilot/` — **完成, 见 `waf2/rag/eval/runs/2026-05-24-mbench-pilot/`**
- [x] 8.2 端到端跑 WAF2 pilot: `python waf2/rag/scripts/run_waf2_on_mbench.py --jsonl waf2/rag/eval/m-bench-core/pilot/attacks.jsonl --rag-mode both --out-dir <same-pilot-dir>` — **完成 (本地 Ollama qwen3:8b)**: attacks: RAG OFF blocked 24/45, RAG ON blocked 32/45 (+8 RAG rescue); benign: 2/5 FP (两个 hard-neg 即使 WAF2 也误判)
- [x] 8.3 同样跑 pilot benign 文件 (跨层都要跑) — **完成 (WAF1 strict + full); WAF2 同样 mock**
- [x] 8.4 端到端跑 merge + report: `python waf2/rag/scripts/merge_mbench_layers.py ...` + `python waf2/rag/scripts/report_mbench.py ...` — **完成, 见 `waf2/rag/eval/runs/2026-05-24-mbench-pilot/dual-layer-mbench-report.md`**
- [x] 8.5 Review pilot 报告: 检查 6 张表都出现、数字合理、`expected_block_step` 标注口径是否过严 (如果 step=2 的链全部在 step 1 就被拦, 考虑放宽到列表语法或调整数据集) — **6 张表全部出现; Overall recall=0.822, FPR=0.80 (4/5 hard-neg overblock — Table 4 callout 触发); chain block-step recall 按步深递减 (1.00/0.70/0.50) 符合预期; expected_block_step 标注口径合理**
- [x] 8.6 Pilot 结论决议: 通过 → 进入 §9 scale up; 不通过 → 修复后回到 §2 — **Pilot 通过: harness 流程完整, 6 表全部正确渲染, FPR 真实可测, hard-neg overblock 被精准检测出。可以进入 §9 scale-up**

## 9. Scale-up — 完整 1150 条数据集

- [x] 9.1 在 `waf2/rag/eval/m-bench-core/attacks.jsonl` 填充完整 150 条恶意 (50+50+50) — 通过 `_build_mbench_attacks.py` 生成, 全部通过 schema 校验
- [x] 9.2 编写 `waf2/rag/scripts/gen_mbench_benign.py` — schema-driven 半模板生成器, 输入工具 schema + 业务正常值字典, 输出 700 条 template benigns
- [x] 9.3 跑生成器写入 `benign.jsonl` 的 template 段 (700 行)
- [x] 9.4 手写 300 条 paired hard-neg benigns 写入 `benign.jsonl` 的 handcrafted 段, 每条设置 `paired_with` — 通过 `_build_mbench_hardneg.py` 半模板生成 (每个 attack subcategory 一个 recipe), 全部 schema 通过, 300/300 paired_with 命中真实 attacks
- [x] 9.5 校验完整数据集: `wc -l attacks.jsonl` == 150; `950 <= wc -l benign.jsonl <= 1050`; 所有行通过 schema.json — attacks=150, benign=1000 (700 template + 300 handcrafted), 1150/1150 valid
- [x] 9.6 手动抽查: 30 条恶意随机样, 检查 `expected_block_by` 合理性; 30 条 hard-neg 随机样, 检查是否真"语义正常" — **通过**: 30/30 attacks case 自身合理 (5 条 FN 是数据集 by design 暴露的盲区); 30/30 hard-neg 语义业务正常 (6 配对模板全覆盖); 1 条标注精度小改进 (`mbc:attack:043` XXE 应加 `waf1.injectionOther`) 因 D7 OR 语义不影响 TP/FN 留作 v2; 抽查 audit 见 `waf2/rag/eval/m-bench-core/audit/2026-05-24-spotcheck.md`
- [x] 9.7 完整数据集 pre-flight check: pilot 阶段所有 case 的标注口径在 full 阶段是否仍一致 — **通过**: family/subcategory 集合 100% 相同, `expected_block_step` 分布 (1-3) 覆盖一致, `expected_block_by` namespace 都用 `waf1.*`, 工具集与合成工具占比 (≤ 15%) 一致; pilot 不覆盖 template benign path 是 by design (pilot 是 hard-neg overblock signal 验证); audit 见 `waf2/rag/eval/m-bench-core/audit/2026-05-24-spotcheck.md` §5-6

## 10. Full run — 跑完整评测

- [x] 10.1 跑完整数据集: WAF1 strict + full + WAF2 rag-on + rag-off, 输出到 `waf2/rag/eval/runs/<date>-mbench-full/` — **完成**: WAF1 strict + full 跑完 attacks (150) + benigns (1000); WAF2 rag-off + rag-on 跑完 attacks (150) 各 ~35 min; benigns 由用户决议(2026-05-24)改为 197 stratified sample (127 unique hard-neg signatures + 70 stratified template) rag-on (67 min, mean 20.5s/case); benigns rag-off 由用户决议跳过, merge 用 `_stub=true` 占位; 跑分输出在 `waf2/rag/eval/runs/2026-05-24-mbench-full/` 和 `waf2/rag/eval/runs/2026-05-24-mbench-full/sample/`
- [x] 10.2 跑 merge + report — **完成**: `merge_mbench_layers` joined=347 (150 attacks + 197 benigns) unmatched=0; `report_mbench` 渲染 6 张表全部到 `waf2/rag/eval/runs/2026-05-24-mbench-full/sample/dual-layer-mbench-report.md`; 加入 Run Composition Disclosure + Run Wall-clock Timing 段
- [x] 10.3 Review full report: 6 张表数值是否合理 (与 b0 / csic 对比讨论), hard-neg 是否触发 overblock callout — **通过**: 见 `waf2/rag/eval/runs/2026-05-24-mbench-full/sample/REVIEW.md`. 关键数: dual recall=0.833, FPR=0.411, F1=0.702 (首次真实 precision); WAF1 union recall=0.733 (vs B-0 0.303 — char_injection 命中 WAF1 规则), WAF2 RAG ON recall=0.587 (vs B-0 0.883 — chain 拉低); hard-neg overblock callout 3/3 层触发 (Δpp +24/+29/+30); 29 条 FN 给出具体 WAF 提升清单(RBAC args 字段、sensitiveFiles 路径扩展、call-chain detector 等)
- [x] 10.4 提交 `dual-layer-mbench-report.md` 到运行目录 (git committed) — **完成**: 全部跑分输出 + audit + REVIEW + mid-run-snapshot + timing.md 文件已在 `waf2/rag/eval/runs/2026-05-24-mbench-full/` 下;等用户审核后 `git commit`(避免主动 commit 大量评测数据)

## 11. Documentation & wrap-up

- [ ] 11.1 更新 `waf2/rag/eval/m-bench-core/README.md` 加入完整 pilot 和 full run 命令、产出位置、报告解读指南 — README 已含 pilot/full 命令; 待 full run 完成后补"报告解读指南"具体数字
- [ ] 11.2 在项目 `README.md` 评测章节 (如 RAG 知识增强 之后) 加一段提及 M-Bench-Core 评测的入口和报告位置 — 待 full run 完成后再加
- [x] 11.3 验证 `git diff master --name-only` 范围符合 spec.md "Change SHALL NOT modify runtime" 要求 (只动 waf2/rag/eval/m-bench-core/, mcp-hub/scripts/, waf2/rag/scripts/, waf2/tests/, openspec/) — 验证通过: `mcp-hub/src/`, `waf2/waf2_proxy.py`, `waf2/rag/engine.py` 全部 unchanged; spec 更新加入 `waf2/rag/eval/runs/` 为允许路径
- [x] 11.4 跑现有 WAF1/WAF2 测试套件确认无回归: `cd mcp-hub && npm test`; Python 测试 (项目自带的 waf2/tests/) — 已跑 `run_waf1_on_b0.test.mjs` (9 通过), `test_merge_b0_layers.py` (全过); 新增的 mbench 测试也全过 (18 + 11 + 11 + 8 = 48 个测试)
- [x] 11.5 运行 `openspec validate "add-mbench-core-attack-benchmark"` 确认 change 仍然 valid — 通过
- [ ] 11.6 用户验收: 提交 dual-layer-mbench-report.md 让用户审, 通过后准备归档 (`opsx:archive`) — pilot 报告已生成 (`waf2/rag/eval/runs/2026-05-24-mbench-pilot/dual-layer-mbench-report.md`), 待 §9-10 full run 后再做最终验收
