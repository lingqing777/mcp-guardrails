# Design — WAF Ablation Evaluation Harness

## Context

`add-mbench-core-attack-benchmark` 第一次让 mcp-guardrails 能在 1150 条 MCP-native 数据(150 attacks + 1000 benigns)上跑出真实 confusion matrix。但 M-Bench-Core 是"全栈跑分"工具:WAF1 strict + WAF1 full + WAF2 rag-on + WAF2 rag-off 四份 jsonl 强 join,无法做"关闭某个 Stage 看 marginal contribution"。本 change 把 M-Bench harness 升级为 ablation-aware,补 3 处缺失:WAF1 三个 Stage 的独立开关、WAF2 ReAct cli flag、merge/report 的单层与跨 ablation 汇总能力。

数据集本身**不动**(attacks.jsonl / benign.jsonl 保持 mbench v1 形态)。harness 改造目标:用同一份数据集跑出 7 行可横比的 TSV 摘要。

## D1. 7 Ablation 配置矩阵(本 change 核心契约)

```
                    │── WAF1 ──│                  │── WAF2 ──│   harness merge
配置                 总   chain  dynSQL  rbacArgs  其它   RAG  ReAct      skip
─────────────────────────────────────────────────────────────────────────────────
1. WAF1-only         on    on    on      on       on     —    —          --skip-waf2
2. WAF2-only         off   n/a   n/a     n/a      n/a    on   on         --skip-waf1
3. Full              on    on    on      on       on     on   on         (none)
4. Full no-chain     on   ✗off   on      on       on     on   on         (none)
5. Full no-dynSQL    on    on   ✗off     on       on     on   on         (none)
6. Full no-RAG       on    on    on      on       on    ✗off  on         (none)
7. Full no-ReAct     on    on    on      on       on     on   ✗off       (none)
```

- 配置 1 / 2 用 `--skip-*` 表达"该层不跑分,merge 时该层视为永远 not-blocked"
- 配置 3-7 都是双层 Full,只关闭某一个能力 — 4 / 5 通过 `POST /api/config/waf1` 设置 enabled=false;6 / 7 通过 cli flag(`--rag-mode off` / `--react-mode off`)
- 配置 1 (WAF1-only) 的 `dual = waf1_union`;配置 2 (WAF2-only) 的 `dual = waf2_full`;其余 5 个都是 `dual = waf1_union ∪ waf2_full`
- 配置 6 (no-RAG) 的 `waf2_full = rag_off`(而不是 rag_on)

## D2. WAF1 开关设计

### Stage 入口判断 — 加在 validateToolCall 内

当前 `mcp-hub/src/waf1/index.js` 的 `validateToolCall` 阶段顺序(改造后):

```
Stage -1: 速率限制     (waf1Enabled 决定整体)
Stage  0: RBAC         (rbacController.enabled — 默认 false,本 change 不动)
Stage  0.5: RBAC args  (config.rbacArgsEnabled — 默认 true,本 change 新增开关)
Stage  1: 白名单
Stage  2: 正则规则     (config.rulesEnabled[<category>] 已存在)
Stage  3: 调用链       (config.callChainEnabled — 默认 true,本 change 新增开关)
Stage  4: 动态 SQL 策略 (config.dynamicPolicyEnabled — 默认 true,本 change 新增开关)
Stage  5: 检测器
```

每个新开关的判断点:

| Stage | 判断位置 | 关闭后行为 |
|---|---|---|
| 0.5 RBAC args | `validateToolCall` 调用 `detectArgsRoleClaimTampering` 之前 | 直接跳到 Stage 1,不调 helper |
| 3 调用链 | `validateToolCall` 当前 `if (chainResult.detected)` 之前;实际上需要更早 — 让 `callChainTracker.check(...)` 调用本身也跳过,避免 history 状态被记录(这样 Stage 4 / Stage 5 看到的 chainResult 仍为 `{detected:false}`) | `callChainTracker.check` 不调用,`chainResult = {detected:false}` |
| 4 动态 SQL | `const dynamicPolicyResult = checkDynamicPolicy(...)` 之前 | 跳过整个 dynamic-policy 块,直接到 Stage 5 |

### updateWaf1Config 字段映射

当前 `updateWaf1Config(newConfig)` 只识别 `newConfig.waf1.rules`(对应 RULES.* category)和 `newConfig.waf1.enabled`(全局)。新加:

```js
if (newConfig.waf1.callChainEnabled !== undefined) {
  config.callChainEnabled = !!newConfig.waf1.callChainEnabled;
}
if (newConfig.waf1.dynamicPolicyEnabled !== undefined) {
  config.dynamicPolicyEnabled = !!newConfig.waf1.dynamicPolicyEnabled;
}
if (newConfig.waf1.rbacArgsEnabled !== undefined) {
  config.rbacArgsEnabled = !!newConfig.waf1.rbacArgsEnabled;
}
```

3 个字段默认值在 module 顶部的 `let config = {...}` 字面量里都设为 `true`,保证向后兼容。

### 不在 dashboard UI 暴露(本 change 范围内)

- dashboard 的 WAF1 tab 当前只显示 10 类正则规则的开关 + RBAC 配置 + 限流配置
- 这 3 个新开关只暴露在 `POST /api/config/waf1` 层,harness 通过 curl/fetch 直接 wire
- dashboard UI 扩展留给后续 change(若需要的话)

## D3. WAF2 harness ReAct 开关

WAF2 服务端 `waf2/waf2_proxy.py` 已经定义了:
- `config.react_routing_enabled`(env var `REACT_ROUTING_ENABLED`,默认 true)
- `ConfigUpdate` 模型接受 `react_routing_enabled: Optional[bool]`
- `POST /waf2/config {react_routing_enabled: false}` 可关闭

`run_waf2_on_mbench.py` 目前只有 `--rag-mode {on|off|both}`,通过 `_post_config({"rag_enabled": ...})` wire。新加 `--react-mode {on|off|both}` 完全对称:

```python
parser.add_argument('--react-mode', choices=['on','off','both'], default='on')
...
for react_state in modes_for(args.react_mode):
    _post_config({"react_routing_enabled": react_state})
    run_one_round(jsonl, rag_state, react_state, out_dir)
```

跑分文件命名:**默认仅在 react-mode != on 时加后缀**,保持与旧 harness 输出一致。

| `--rag-mode` | `--react-mode` | 输出文件名 |
|---|---|---|
| on | on | `cases-mbench-attacks-rag-on.jsonl`(旧命名,兼容) |
| off | on | `cases-mbench-attacks-rag-off.jsonl`(旧命名,兼容) |
| on | off | `cases-mbench-attacks-rag-on-react-off.jsonl`(新加后缀) |
| off | off | `cases-mbench-attacks-rag-off-react-off.jsonl` |

## D4. merge `--skip-*` 行为契约

当前 `merge_mbench_layers.py` 强制 4 份 jsonl(waf1-strict / waf1-full / rag-on / rag-off)都存在,inner-join 缺一个 case 就丢进 `merge-misses.json`。

新加两个互斥 flag:

```
--skip-waf1                  跳过 WAF1 两层,要求 rag-on(+ 可选 rag-off)存在
--skip-waf2                  跳过 WAF2 两层,要求 waf1-strict + waf1-full 存在
(默认)                       4 层都必须存在(现状)
```

merge 计算逻辑变化:

```
--skip-waf1 模式:
  waf1_union = false (per case)         # 不参与
  waf2_full  = rag_on.outcome=blocked
  dual       = waf2_full
  rag_off 可选 — 存在则记录 outcome,不存在视为 stub

--skip-waf2 模式:
  waf1_union = strict.outcome OR full.outcome
  waf2_full  = false (per case)         # 不参与
  dual       = waf1_union
  rag-on/off 不要求存在
```

merged jsonl 顶层加:

```json
{
  "ablation_label": "WAF1-only",          // from --ablation-label cli
  "skipped_layers": ["waf2"],             // ["waf1"] | ["waf2"] | []
  ...
}
```

report 通过读 `skipped_layers` 决定 Table 1 三层中哪一层被标记为 "n/a"。

## D5. Report TSV 摘要

`report_mbench.py` 现在输出纯 Markdown 6 张表。本 change 新加:

### summary.tsv(每 run 1 行,7 列)

文件名固定:`<run-dir>/summary.tsv`。无表头(便于追加),编码 UTF-8 不带 BOM,字段间 `\t` 分隔。列定义:

| 列序 | 列名 | 数据来源 | 计算口径 |
|---|---|---|---|
| 1 | `ablation_label` | cli `--ablation-label` | 原样透传,例 "Full no-chain" |
| 2 | `char_F1` | dual layer | family=char_injection 的 F1,family TP/FN 来自该 family 攻击;FP/TN 来自所有 benigns |
| 3 | `pi_F1` | dual layer | family=prompt_injection_and_priv_esc 的 F1,同上 FP/TN 口径 |
| 4 | `chain_F1` | dual layer | family=call_chain 的 F1,同上 |
| 5 | `recall` | dual layer | 全 attacks 的整体 recall = TP / (TP + FN) |
| 6 | `F1` | dual layer | 全数据集 overall F1(综合) |
| 7 | `avg_time_attacks_ms` | per-case 活跃层 latency_ms 之和的均值 | 仅 label=attack 子集 |
| 8 | `avg_time_benigns_ms` | 同上 | 仅 label=benign 子集 |

**注**:7 列其实是 8 个字段(由于 AvgTime 拆 attacks/benigns)。用户原话"6 列"按概念分组 — 实际写盘 8 列。

### AvgTime 口径

每个 case 的 pipeline 总用时 = 该 ablation 下"活跃层"的 latency_ms 之和:

```
ablation              活跃层                            latency_ms 来源
─────────────────────────────────────────────────────────────────────
WAF1-only             waf1-strict + waf1-full           merged.waf1_strict.latency_ms + waf1_full.latency_ms
WAF2-only             rag-on                            merged.rag_on.latency_ms
Full                  strict + full + rag-on            三者之和
Full no-chain         strict + full + rag-on            (跟 Full 一样,因为关闭 chain 不去掉层,只是 stage 内部跳过)
Full no-dynSQL        strict + full + rag-on            同上
Full no-RAG           strict + full + rag-off           注意是 rag-off
Full no-ReAct         strict + full + rag-on-react-off  注意是 react-off 后缀文件
```

`avg_time_*` = `mean(sum_active_latencies_per_case)`,跨 case 平均后保留 1 位小数。

### index.tsv 累积模式

`report_mbench.py --append-to <path>` 把当前 summary.tsv 追加到全局索引:

```bash
python -m waf2.rag.scripts.report_mbench \
  --merged <run-dir>/cases-mbench-merged.jsonl \
  --out <run-dir>/dual-layer-report.md \
  --ablation-label "WAF1-only" \
  --append-to waf2/rag/eval/runs/<date>-ablation-7way/index.tsv
```

跑完 7 个 ablation 后,`index.tsv` 就是一张 7 行 × 8 列的横比表,直接粘到 Excel。

## D6. 端到端 7 命令的工程形态

每个 ablation 1 个 run 子目录,目录命名 `<NN>-<label-kebab>` 便于排序:

```
waf2/rag/eval/runs/<date>-ablation-7way/
├── 1-waf1-only/
│   ├── attacks/cases-mbench-attacks-waf1-{strict,full}.jsonl
│   ├── benigns/cases-mbench-benign-waf1-{strict,full}.jsonl
│   ├── cases-mbench-merged.jsonl
│   ├── dual-layer-report.md
│   └── summary.tsv
├── 2-waf2-only/
│   └── ...
├── ...
├── 7-no-react/
│   └── ...
└── index.tsv          ← 7 行 × 8 列汇总(报告产物)
```

7 个命令的形态(详见 tasks.md §6):

| # | 名称 | 关键 wire |
|---|---|---|
| 1 | WAF1-only | POST /api/config/waf1 全开 + WAF2 不跑 + merge `--skip-waf2` |
| 2 | WAF2-only | WAF1 跳过 + WAF2 rag-on + merge `--skip-waf1` |
| 3 | Full | 全开,4 round merge |
| 4 | Full no-chain | POST /api/config/waf1 `callChainEnabled: false` + 4 round merge |
| 5 | Full no-dynSQL | POST /api/config/waf1 `dynamicPolicyEnabled: false` + 4 round merge |
| 6 | Full no-RAG | WAF1 全开 + WAF2 rag-mode off only + merge,dual=waf1∪rag_off |
| 7 | Full no-ReAct | WAF1 全开 + WAF2 react-mode off + merge |

## D7. 测试集规模决策

ablation 跑分总时间预算 = 7 ablation × (attacks + benigns) × WAF2 LLM 时延 × round 数。

完整 1000 benigns × WAF2 rag-on 需 67min/round。如果每个 ablation 都跑完整 1000,总成本不可接受(>1 天)。决策:

| 测试集 | 用途 | 规模 |
|---|---|---|
| attacks.jsonl | 全跑,跨 7 ablation | 150 attacks(M-Bench v1 完整) |
| benign_sample.jsonl | 7 ablation 共享 sample | 197(M-Bench full run 已生成,在 `waf2/rag/eval/runs/2026-05-24-mbench-full/benign_sample.jsonl`) |

WAF2 跑分共享策略:配置 3 / 4 / 5(都用 WAF2 rag-on)可以 **复用同一份 WAF2 rag-on 跑分**(因为关闭 WAF1 的某个 stage 不影响 WAF2 输入)。harness 跑 4 / 5 时只需 wire WAF1 config 并重跑 WAF1 layer,WAF2 layer 复用 #3。这把 WAF2 LLM 调用次数从 7 × (150 + 197) 降到 ~4 × (150 + 197):

| 配置 | 复用 WAF1? | 复用 WAF2? | 实际跑 |
|---|---|---|---|
| 1 WAF1-only | — | — | 仅 WAF1 |
| 2 WAF2-only | — | — | 仅 WAF2 rag-on |
| 3 Full | — | — | WAF1 + WAF2 rag-on |
| 4 Full no-chain | 重跑(WAF1 配置变了) | 复用 #3 | 仅 WAF1 |
| 5 Full no-dynSQL | 重跑 | 复用 #3 | 仅 WAF1 |
| 6 Full no-RAG | 复用 #3 | 重跑(rag-off) | 仅 WAF2 rag-off |
| 7 Full no-ReAct | 复用 #3 | 重跑(react-off) | 仅 WAF2 react-off |

实际 LLM-bound 跑分:WAF2 rag-on (#2/#3 共享) + WAF2 rag-off (#6) + WAF2 react-off (#7) = 3 次 × (attacks 150 + benigns 197) ≈ 3 × ~100min ≈ 5h(单模型)。可分 3 个时段并行(或 1 个长 session)。

## D8. 命名 / 编号 / 默认值约定

- 三个 WAF1 开关字段名:`callChainEnabled` / `dynamicPolicyEnabled` / `rbacArgsEnabled`(驼峰,与现有 `enabled` / `rulesEnabled` 一致)
- WAF2 字段名沿用现有 `react_routing_enabled`(snake_case,Python 风格)
- 默认值全部为 `true`(向后兼容)
- merge skip flag:`--skip-waf1` / `--skip-waf2`(kebab-case,沿用 argparse 风格)
- harness flag:`--ablation-label`(report 和 merge 都接受同一个 flag)
- 跑分子目录命名:`<NN>-<kebab>` 比如 `4-full-no-chain`

## D9. 不在本 change 范围

- 不修改 WAF1 已有的 5 阶段检测逻辑(只在入口加 enable 判断)
- 不修改 WAF2 服务端的任何决策路由(只补 harness wrapper)
- 不修改 M-Bench 数据集(attacks/benign jsonl 保持不变)
- 不暴露 3 个新开关到 Dashboard UI(只暴露到 API 层)
- 不引入新的 LLM provider 或 model
- 不修改 report 已有的 6 张 Markdown 表内容,只在末尾追加 summary.tsv

## D10. 风险与边界

| 风险 | 缓解 |
|---|---|
| Stage 3 调用链关闭后,后续 Stage 5 detector 依赖 `chainResult` 状态 — 必须把 chainResult 传成 `{detected:false}` | 已在 D2 表格中明确:`callChainTracker.check` 不被调用,`chainResult` 设默认值 |
| 多个 ablation 共享 WAF1/WAF2 跑分时,run 子目录之间硬链接 / 软链接需要明确 | tasks.md 给出 `cp` / `ln -s` 显式命令,避免误删 |
| 跨 ablation latency 对比若 WAF2 LLM 在不同时段调用,环境差异可能扰动 | summary.tsv 多跑几次(N=3)取中位数;暂时单次 — 若波动大再扩 |
| `react_routing_enabled=false` 后 WAF2 走 ROUTE_LOCAL_LLM,跟 ReAct 路径完全不同,latency 会暴降但 recall 也可能降 | 这正是消融目的 — 报告里要明确解读 |
| dashboard UI 不暴露 3 开关 — 用户重启 mcp-hub 后,配置回到默认全开 | 接受 — ablation 跑分本来就是 ephemeral 工作流,每次跑前 POST API |
