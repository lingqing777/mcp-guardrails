# Tasks — WAF Ablation Evaluation Harness

## 1. WAF1 Stage 独立开关 — mcp-hub/src/waf1/

- [x] 1.1 `index.js`:在模块顶部 `let config = {...}` 字面量加 3 个默认值字段:`callChainEnabled: true`、`dynamicPolicyEnabled: true`、`rbacArgsEnabled: true`
- [x] 1.2 `index.js`:`updateWaf1Config(newConfig)` 增加 3 段 `if (newConfig.waf1.<field> !== undefined) config.<field> = !!newConfig.waf1.<field>`
- [x] 1.3 `index.js`:`validateToolCall` Stage 0.5 入口加 `if (config.rbacArgsEnabled) { ... 现有 detectArgsRoleClaimTampering 块 ... }`
- [x] 1.4 `index.js`:`validateToolCall` Stage 3 改造 — 用 `const chainResult = config.callChainEnabled ? callChainTracker.check(...) : { detected: false }`,既跳过 `check()` 调用也保证 chainResult 下游使用安全
- [x] 1.5 `index.js`:`validateToolCall` Stage 4 入口加 `if (config.dynamicPolicyEnabled) { ... 现有 checkDynamicPolicy 块 ... }`
- [x] 1.6 `index.test.js`:新增 11 个 vitest case 覆盖三个开关的 on / off 行为 + updateWaf1Config 透传(覆盖 spec 全部 11 个 scenarios,超出最初估计的 6 个)
- [x] 1.7 跑 `cd mcp-hub && npm test` 验证 53 → **64** 全过(53 旧 + 11 新)

## 2. 配置 API 透传 — mcp-hub/src/api/

- [x] 2.1 找到 `POST /api/config/waf1` 路由源文件 — 确认在 `mcp-hub/src/api/config.js:209-232`
- [x] 2.2 在该路由 handler 中,把 request body 的 `callChainEnabled` / `dynamicPolicyEnabled` / `rbacArgsEnabled` 三个字段透传到 `config.waf1.*` 然后调 `updateWaf1Config(config)`;同时 `saveGuardrailsConfig` 会把新字段持久化到 `config/guardrails-config.json`(向后兼容 — 老 config 没字段时,运行时仍使用 module 顶部默认 true)
- [x] 2.3 手工 curl 验证命令(留给服务起来后跑):
  ```bash
  # 关闭调用链 detector
  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"callChainEnabled":false}' \
    http://localhost:4000/api/config/waf1 | jq

  # 反查
  curl -s http://localhost:4000/api/config | jq '.waf1.callChainEnabled'
  ```

## 3. WAF2 harness ReAct flag — waf2/rag/scripts/

- [x] 3.1 `run_waf2_on_mbench.py`:加 `--react-mode {on|off|both}` argparse 配置,默认 `'on'`
- [x] 3.2 重构 round 循环为 `for rag_state in modes_for(args.rag_mode): for react_state in modes_for(args.react_mode):`(嵌套)— 抽出新模块级函数 `compute_rounds(rag_mode, react_mode) -> list[(slug, cfg)]`,便于单元测试,main() 改为单行调用
- [x] 3.3 在每个 round 开始前,把 `react_routing_enabled` 一并写入 `POST /waf2/config` body(与现有 `rag_enabled` 同次请求)
- [x] 3.4 输出文件命名规则:`react_state == 'on'` 时不加后缀(保持旧文件名兼容);否则文件名追加 `-react-off` 段(如 `cases-mbench-attacks-rag-on-react-off.jsonl`)
- [x] 3.5 在 `test_run_waf2_on_mbench.py` 中追加 7 个 compute_rounds 测试:覆盖默认 / rag-both / react-off / rag-off+react-off / react-both / both×both / payload 字段完整性。全 18/18 通过(11 旧 + 7 新);merge / report 现有测试也未 break

## 4. merge `--skip-*` + `--ablation-label` — waf2/rag/scripts/

- [x] 4.1 `merge_mbench_layers.py`:加 argparse `--skip-waf1` / `--skip-waf2` / `--ablation-label <str>`
- [x] 4.2 在 join 函数前加 mutual-exclusive 校验 — 两个 skip 同时 set 则 exit 2 with message "at least one layer must be evaluated"
- [x] 4.3 修改 4-layer 强制 join 逻辑 — `--skip-waf1` 模式只加载 rag-on(+ 可选 rag-off);`--skip-waf2` 模式只加载 waf1-strict + waf1-full;无 skip 时仍 4 层(rag-off 在新代码里也变为可选,只要存在就参与 join)
- [x] 4.4 修改 dual 计算 — skip 模式下 dual = 剩下那层的 OR(skip waf1 → dual=waf2_blocked;skip waf2 → dual=waf1_union_blocked)
- [x] 4.5 merged JSONL 顶层加 `ablation_label` + `skipped_layers` 字段;每个被 skip 的 nested layer(`waf1_strict`/`waf1_full`/`rag_on`/`rag_off`)加 `_skipped: true` 标记;`merge-misses-mbench.json` 也包含 `skipped_layers` 和 `ablation_label`
- [x] 4.6 在 `test_merge_mbench_layers.py` 追加 4 个测试覆盖:`--skip-waf2`(WAF1 驱动 dual)、`--skip-waf1`(WAF2 驱动 dual)、两个 skip 互斥校验、`--ablation-label` 传播。15/15 全过(11 旧 + 4 新);report_mbench 测试也未 break

## 5. report TSV + `--append-to` + `--ablation-label` — waf2/rag/scripts/

- [x] 5.1 `report_mbench.py`:加 argparse `--ablation-label <str>` / `--append-to <path>`
- [x] 5.2 在 Markdown 报告写完之后,新增 `write_summary_tsv(out_dir, ablation_label, metrics)` 函数:输出 1 行 8 字段 TSV 到 `<out-dir>/summary.tsv`
- [x] 5.3 实现 AvgTime 计算:对每个 case 累加该 ablation 下"活跃层"的 latency_ms(strict / full / rag-on / rag-off-react-off 等),按 `label=attack` / `label=benign` 分组取均值 — 新函数 `compute_avg_time_ms(records, label)`
- [x] 5.4 活跃层判断逻辑:读 merged JSONL 的 `skipped_layers` + `_skipped`/`_stub` 标记 — 新函数 `active_layers(record)` 返回 slot 名列表
- [x] 5.5 实现 `--append-to`:`append_to_index(path, label, metrics)` 把 summary 一行追加到指定 index 路径,缺则创建;ablation_label cli 缺省时退回到 merged 第一行的 `ablation_label` 字段
- [x] 5.6 在 `test_report_mbench.py` 追加 10 个测试覆盖:active_layers 在 full/skip-waf1/skip-waf2 3 种模式、AvgTime full / WAF1-only、format_tsv 8 字段、label 净化、write_summary_tsv 1 行结构、append_to_index 累积、compute_summary_metrics 端到端 + e2e smoke 跑真实 347-case merged.jsonl 验证数字(recall=0.833 / F1=0.702 / AvgTime atk=28033ms)与 mbench-full 报告完全一致。18/18 全过(8 旧 + 10 新)

## 6. 端到端 7 命令脚本 — waf2/rag/scripts/

- [x] 6.1 创建 `waf2/rag/scripts/run_ablation.sh`(bash 脚本):接受 `--ablation <1..7|all>` / `--date <YYYY-MM-DD>` / `--model <name>` / `--attacks <path>` / `--benigns <path>` / `--root <dir>` / `--mcp-hub <url>` / `--waf2 <url>`
- [x] 6.2 脚本顶部加 comment 块,显式列出 7 ablation 的 wire 顺序(参见 design.md D6)
- [x] 6.3 实现配置 1 (WAF1-only):`post_waf1 true true true` → `run_waf1 attacks` + `run_waf1 benigns` → `run_merge_and_report --skip-waf2` (label="WAF1-only")
- [x] 6.4 实现配置 2 (WAF2-only):`post_waf2 true true` → `run_waf2 attacks/benigns on on` → `run_merge_and_report --skip-waf1` (label="WAF2-only")
- [x] 6.5 实现配置 3 (Full):`post_waf1` + `post_waf2` 全开 → WAF1 + WAF2 (rag-mode both, react on) 4 round → merge (no skip)
- [x] 6.6 实现配置 4 (no-chain):`post_waf1 false true true` → 跑 WAF1 → `reuse_waf2_from_full` cp 配置 3 的 rag-on + rag-off → merge → report
- [x] 6.7 实现配置 5 (no-dynSQL):`post_waf1 true false true` → 跑 WAF1 → `reuse_waf2_from_full` cp 配置 3 → merge → report
- [x] 6.8 实现配置 6 (no-RAG):`run_waf2 ... off on` → `slot_rag_off_as_rag_on`(mv rag-off → rag-on)→ `reuse_waf1_from_full` cp 配置 3 WAF1 → merge → report
- [x] 6.9 实现配置 7 (no-ReAct):`run_waf2 ... on off` → `slot_react_off_as_rag_on`(mv rag-on-react-off → rag-on)→ `reuse_waf1_from_full` → merge → report
- [x] 6.10 dispatcher case 支持 `--ablation all`,顺序跑 1→7;配置 4/5/6/7 显式校验 `3-full/` 目录存在(否则 exit 3)
- [x] 6.11 输出统一目录 `waf2/rag/eval/runs/<date>-ablation-7way[-<model>]/{1-waf1-only,...,7-full-no-react}/`,每个子目录含 `cases-mbench-merged.jsonl` + `dual-layer-mbench-report.md` + `summary.tsv`;`<root>/index.tsv` 由 `--append-to` 累积;结尾打印 `cat <root>/index.tsv` 提示
- [x] 6.12 (额外)`normalize_{attacks,benign}_outputs` 处理用户自定义 jsonl 文件名(stem != "attacks"/"benign")时把 WAF1/WAF2 harness 输出 rename 成 merge 期望的 split 命名;`prepare_dataset_dir` 在每个 ablation 目录下 cp attacks.jsonl + benign.jsonl 进 `_dataset/`,merge 用之

## 7. 文档与示例

- [ ] 7.1 新建 `waf2/rag/scripts/README.md` 或扩展现有 README,加 "Ablation evaluation harness" 章节,粘贴 7 条 wrapper 命令 + 预期产物结构
- [ ] 7.2 `waf2/rag/eval/m-bench-core/README.md` 增加一条 "Ablation evaluation: see add-waf-ablation-eval-harness change for harness usage"

## 8. 验证

- [ ] 8.1 跑 `openspec validate add-waf-ablation-eval-harness --strict`,所有 requirement 必须 ≥ 1 scenario
- [ ] 8.2 跑 `cd mcp-hub && npm test` 验证现有 + 新 vitest 全过
- [ ] 8.3 跑 `pytest waf2/tests/test_merge_mbench_layers.py waf2/tests/test_report_mbench.py` 验证 Python 测试全过
- [ ] 8.4 端到端 smoke test:用 5 条 attacks + 5 条 benigns 跑 7 ablation,确认 `<root>/index.tsv` 有 7 行且每行 8 字段
- [ ] 8.5 在 pilot 5×5 通过后,正式跑 150 attacks + 197 benigns sample × 7 ablation,产出 final `index.tsv`
- [ ] 8.6 用户审阅 `index.tsv`,通过后准备归档 change

## 9. 不在本 change 范围

- 不在 Dashboard UI 暴露 3 个 WAF1 新开关(本 change 仅 API 层)
- 不修改 m-bench-core 数据集(沿用 attacks.jsonl / benign.jsonl)
- 不引入新 LLM provider,只复用现有 qwen3:8b via Ollama
- 不对 6 张 Markdown 表内容做更改(仅在末尾追加 summary.tsv 一行)
- 不写 dashboard 测试
