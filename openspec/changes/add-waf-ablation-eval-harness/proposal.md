# WAF Ablation Evaluation Harness

## Why

M-Bench-Core 第一次让本项目能在 MCP-native 数据集上跑出真实 precision / recall / F1 / FPR(见 `add-mbench-core-attack-benchmark`)。但 M-Bench 当前只支持"WAF1 全开 + WAF2 全开"两种主轴(rag-on / rag-off),无法回答:

1. **WAF1 各阶段的边际贡献** — 把调用链 detector 关掉,recall 会掉多少?把动态 SQL 策略关掉,supabase trifecta 还能不能拦?把上轮新增的 Stage 0.5(RBAC args 篡改)关掉,RBAC bypass 案例又回到 FN?
2. **WAF2 各能力的边际贡献** — RAG 知识增强对哪类家族有效?ReAct 深度推理在 prompt injection 上是 +0 还是 +20pp?
3. **WAF1-only / WAF2-only 的"基线 vs 全栈"差距** — 单层 WAF 与双层串联各自能拿到多少 recall,差距是不是真的足够大到值得双层架构。

现有 harness 不支持这些消融,主要缺三样东西:

- **WAF1 没有调用链 / 动态 SQL / Stage 0.5 RBAC args 的独立开关** —— 只有 `setWaf1Enabled` 这个总闸,无法精确关掉某一 Stage
- **WAF2 harness 没有 ReAct 开关** —— WAF2 服务本身已有 `react_routing_enabled` 字段(`POST /waf2/config`),但 `run_waf2_on_mbench.py` 没有 cli flag 来 wire 这个字段
- **merge / report 不支持单层评测口径** —— `merge_mbench_layers.py` 严格要求 WAF1 strict + WAF1 full + rag-on + rag-off 四份 jsonl 都存在,跑 WAF1-only / WAF2-only 时 dual 计算会出错;`report_mbench.py` 也只输出 6 张 Markdown 表,没有"每 run 一行 TSV 摘要"以便跨 ablation 横比

为了把"评估边际贡献 + 跨 ablation 横比"做成可复现、可分配给多模型的工作流,需要新增三件套:**WAF1 三个 Stage 独立开关、WAF2 harness ReAct flag、merge/report 的 ablation-aware 输出**。

## What Changes

- **WAF1 三个独立 Stage 开关**(`mcp-hub/src/waf1/`):
  - `config.waf1.callChainEnabled`(默认 `true`)—— 控制 Stage 3 调用链 detector 是否在 `validateToolCall` 中被调用
  - `config.waf1.dynamicPolicyEnabled`(默认 `true`)—— 控制 Stage 4 `checkDynamicPolicy` 是否在 `validateToolCall` 中被调用
  - `config.waf1.rbacArgsEnabled`(默认 `true`)—— 控制 Stage 0.5 `detectArgsRoleClaimTampering` 是否在 `validateToolCall` 中被调用
  - `updateWaf1Config` 接受三个新布尔字段,运行时透传至各 stage 判断
  - `POST /api/config/waf1` 接受三个新字段(向后兼容 — 未传时保持当前 enabled 状态)

- **WAF2 harness ReAct 开关**(`waf2/rag/scripts/run_waf2_on_mbench.py`):
  - 新增 `--react-mode {on|off|both}` cli flag(语义对齐现有 `--rag-mode`)
  - flag 通过 `POST /waf2/config {react_routing_enabled: bool}` wire 到 WAF2 服务
  - 跑分输出文件名加 round 后缀:`cases-mbench-*-react-{on,off}.jsonl`(only when `--react-mode != on` for backward compat)

- **merge 层 ablation skip**(`waf2/rag/scripts/merge_mbench_layers.py`):
  - 新增 `--skip-waf1` flag — WAF1 strict + WAF1 full 两份 jsonl 不要求存在;`waf1_union` 视为永远 not-blocked;`dual = rag_on`(或当前活跃的 WAF2 round)
  - 新增 `--skip-waf2` flag — rag-on + rag-off 不要求存在;`waf2_full` 视为永远 not-blocked;`dual = waf1_union`
  - 两个 skip 互斥,且至少一层必须有数据
  - merged jsonl 顶层加 `ablation_label` 字段(从 cli `--ablation-label` 注入)

- **report 层 TSV 摘要 + ablation 标签**(`waf2/rag/scripts/report_mbench.py`):
  - 新增 `--ablation-label "<text>"` flag —— 透传到 `summary.tsv` 第一列
  - 末尾输出 `<run-dir>/summary.tsv` —— 1 行,7 列:
    ```
    ablation_label \t char_F1 \t pi_F1 \t chain_F1 \t recall \t F1 \t avg_time_attacks_ms \t avg_time_benigns_ms
    ```
  - F1 / recall 全部基于 dual 层(`waf1_union ∪ waf2_full`,在 skip 模式下退化为单层)
  - AvgTime 按 `label=attack` 和 `label=benign` 分组,基于该 ablation 下活跃层的 `latency_ms` 之和(单 case 的 pipeline 总用时)
  - 新增 `report_mbench.py --append-to <index.tsv>` 模式 —— 把当前 summary.tsv 追加到全局索引,方便跨 ablation 7 行汇总

- **不修改**:
  - 数据集 `attacks.jsonl` / `benign.jsonl`(M-Bench-Core change 的产物保持不变)
  - WAF1 已有的规则数组、检测器逻辑 — 只在 stage 入口加 `if (enabled)` 判断
  - WAF2 服务端 `waf2_proxy.py` — `react_routing_enabled` 字段已存在,只是 harness 端补 wire
  - Dashboard UI(本 change 不暴露三个新开关到 dashboard,仅 API 层)

## Capabilities

### New Capabilities

- `waf-ablation-evaluation`: 定义 7 种消融配置的精确语义(WAF1-only / WAF2-only / Full / Full-no-chain / Full-no-dynSQL / Full-no-rag / Full-no-react)、harness 在各配置下应 wire 哪些开关、merge 层 `--skip-*` 行为契约、report 输出的 TSV 摘要格式(列定义 + AvgTime 口径)、跨 ablation `index.tsv` 累积约定。

### Modified Capabilities

- `waf1`: 新增 3 个 Requirement,声明 Stage 0.5 / Stage 3 / Stage 4 必须有独立配置开关、`updateWaf1Config` 接受这些字段、配置缺失时各 stage 保持启用(默认 true)。不破坏既有 5 阶段流水线契约,只在每个 stage 入口加 enable 判断。

## Impact

- `mcp-hub/src/waf1/index.js`:`config` 默认值加 3 个 enabled 字段;`validateToolCall` Stage 0.5 / Stage 3 / Stage 4 各加 1 行 enable 判断;`updateWaf1Config` 处理 3 个新字段
- `mcp-hub/src/api/config.js`(或当前 `/api/config/waf1` 路由所在文件):透传 3 个新字段到 `updateWaf1Config`
- `waf2/rag/scripts/run_waf2_on_mbench.py`:加 `--react-mode` 解析、wire 到 `POST /waf2/config`、round 名加后缀
- `waf2/rag/scripts/merge_mbench_layers.py`:加 `--skip-waf1` / `--skip-waf2` / `--ablation-label`
- `waf2/rag/scripts/report_mbench.py`:加 `--ablation-label` / `--append-to`,末尾写 `summary.tsv`,F1/recall/AvgTime 计算适配 skip 模式
- 新增评测目录约定 `waf2/rag/eval/runs/<date>-ablation-7way/{1-waf1-only,...,7-no-react}/` —— 每个 ablation 一个子目录
- 不影响 `add-mbench-core-attack-benchmark` change 的归档(数据集与 harness 入口脚本兼容,新 flag 默认行为等同旧行为)
