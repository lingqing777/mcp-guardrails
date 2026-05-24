# M-Bench-Core: 自建 MCP 核心攻击基准数据集

## Why

当前 mcp-guardrails 的评测体系有三个结构性缺口,无法支撑参赛/裁判演示阶段对"系统真实检测能力"的客观度量:

1. **没有 MCP-native 形状的样本** — 现有 CSIC2010 (~61k) 和 B-0 prompt-injection (228) 都是 HTTP 流量形状,跑 WAF1 必须靠 `tools/call(http_request, body=...)` 这个"假包装"才能喂进流水线。这绕开了真实场景里的 `tools/call(<server>__<tool>, <args>)` envelope (例如 `tools/call(woocommerce__create_product, {name:..., price:...})`),无法暴露 WAF1 在真实 MCP 工具调用形状下的检测盲区。
2. **调用链组合攻击没有任何静态数据集** — `mcp-hub/src/waf1/call-chain.js` 定义了 4 种危险链 (`data_exfiltration` / `credential_theft` / `recon_then_exploit` / `supabase_lethal_trifecta`),但只能在线追踪,不存在任何 jsonl 文件能离线评测它,无法回答"WAF1 调用链检测器实际拦得下多少链路攻击"。
3. **良性样本极少且形态不对** — `waf2/rag/data/seeds/benign_hard_negatives.jsonl` 只有 10 条自然语言文本 (教程/讨论),没有 MCP 工具调用形状的良性样本。CSIC 虽有 25k normal,但形状仍是 HTTP,且不包含"参数形态接近恶意但语义正常"的 hard negative。这导致 B-0 评测报告必须在 "precision=1 假设" 下声明 F1 等价于 recall — **FPR 不可测**。

构建 M-Bench-Core 同时补齐这三个缺口,产出一个 ~1150 条 MCP-native 数据集 (150 恶意 + 1000 良性),首次让 mcp-guardrails 能跑出**真实的 precision / recall / F1 / FPR**。

## What Changes

- **新建 MCP-native 攻击数据集** `waf2/rag/eval/m-bench-core/attacks.jsonl` (150 条):
  - 字符注入家族 50 条 (SQLi / XSS / 命令注入 / 路径穿越 / SSRF / XXE),全部包装为 `tools/call(<real_mcp_tool>, <args>)` 形状
  - 提示注入与越权家族 50 条 (direct/indirect PI、tool_poisoning、RBAC bypass、scope_escalation)
  - 调用链组合家族 50 条 — **首次引入多步样本**: `steps: [{tool, args}, ...]` + `expected_chain` + `expected_block_step`
- **新建 MCP-native 良性数据集** `waf2/rag/eval/m-bench-core/benign.jsonl` (~1000 条):
  - 700 条 schema-driven 半模板生成 (覆盖每个真实工具的正常参数取值)
  - 300 条手写 hard-negative (与具体恶意样本 paired,通过 `paired_with` 字段关联)
- **新建评测 harness 脚本**:
  - `mcp-hub/scripts/run_waf1_on_mbench.mjs` — WAF1 strict + full 双变体跑分,多步样本逐步喂入 (在 `expected_block_step` 或更早拦下记 TP);每个 case 之间 `resetWaf1State()` 防止 5 分钟时间窗口污染
  - `waf2/rag/scripts/run_waf2_on_mbench.py` — WAF2 (含 RAG) 跑单步样本;多步样本仅评测最后一步 (WAF2 无会话感知)
  - `waf2/rag/scripts/merge_mbench_layers.py` — 跨层 join,输出 `cases-mbench-merged.jsonl` 和 `dual-layer-mbench-report.md`
  - `waf2/rag/scripts/report_mbench.py` — 渲染最终报告 (家族×层级 confusion / hard-neg vs 模板 FPR / 调用链按 `expected_block_step` 分组 recall)
- **新建 JSON Schema 校验** `waf2/rag/eval/m-bench-core/schema.json` — 单步样本 + 多步样本两套 schema
- **新建数据集 README** `waf2/rag/eval/m-bench-core/README.md` — 数据集说明、与 CSIC/B-0 关系、复现指南、ground truth 标注约定
- **case_id 跨层 join 规则** — 沿用 b0 / csic 模式: `mbc:waf1-strict:<index>` / `mbc:waf1-full:<index>` / `mbc:rag-on:<index>` / `mbc:rag-off:<index>`
- **不修改** WAF1 / WAF2 / RAG 的任何运行时行为 — 这个 change 只新增评测能力

## Capabilities

### New Capabilities

- `m-bench-core-evaluation`: 自建 MCP 核心攻击基准的数据集形状契约 (单步 + 多步样本 schema)、ground truth 标注规则 (`expected_block_by` / `expected_chain` / `expected_block_step` / `paired_with`)、harness 行为契约 (多步样本 step-by-step 评测、WAF1 状态隔离、case_id 跨层 join)、报告内容契约 (家族 confusion、hard-neg vs 模板 FPR、按 expected_block_step 分组的链路 recall)。

### Modified Capabilities

无 — 本 change 不修改任何现有 capability 的 requirement,只新增数据集与评测脚本。`waf1` / `waf2` / `waf1-evaluation` / `b0-evaluation` 等现有 spec 不受影响。

## Impact

**新增文件**:
- `waf2/rag/eval/m-bench-core/{attacks.jsonl, benign.jsonl, schema.json, README.md}` (数据)
- `mcp-hub/scripts/run_waf1_on_mbench.mjs` + `.test.mjs` (Node harness + 测试)
- `waf2/rag/scripts/{run_waf2_on_mbench.py, merge_mbench_layers.py, report_mbench.py}` (Python harness)
- `waf2/tests/test_{run_waf2_on_mbench,merge_mbench_layers,report_mbench}.py` (Python 测试)
- `waf2/rag/eval/runs/<date>-mbench-pilot/` 和 `<date>-mbench-full/` (评测产出目录)
- `openspec/specs/m-bench-core-evaluation/spec.md` (归档后)

**不动**:
- WAF1 中间件 (`mcp-hub/src/waf1/`) — 行为不变,仅作为评测客体
- WAF2 代理 (`waf2/waf2_proxy.py`) — 行为不变
- MCP Hub 路由注册顺序、Dashboard、Docker 编排、认证模块 — 全部不动
- 不增加运行时依赖 (Node/Python 都用项目已有依赖)

**Docker / docker-compose**: 不修改 — harness 是离线脚本,不进 Docker 容器,直接调用 WAF1 模块和 WAF2 容器现有 API。

**Dashboard 5 秒刷新**: 不影响 — 评测脚本完全离线,不经过 Dashboard 也不写运行时统计。

**对现有评测的关系**:
- **互补,不取代** CSIC / B-0 / adversarial / InjecAgent
- CSIC 仍是大规模 HTTP-shaped 真实流量基准 (61k 条体量优势)
- B-0 仍是 PI 专项基准 (228 条已稳定)
- M-Bench-Core 填补 MCP-native 形状 + 调用链 + 可测 FPR 的空白
- 现有的 dual-layer 报告 harness (`merge_csic_layers.py` / `merge_b0_layers.py`) 模式被复用,但 case_id schema 不冲突

**已知风险与缓解**:
- 数据集人工构造带来标注偏差 — 用 paired hard-negative + 半模板生成两种来源对冲,且 README 公开标注口径
- 调用链 5 分钟时间窗口在 harness 内部串行执行时可能污染 — design.md 强制要求每个 case 前 `resetWaf1State()`
- 工具 universe 是 "真实为主 + 少量合成填缺",合成工具的检测难度可能高估或低估 — 报告里强制按 "真实 vs 合成" 切分 recall,让裁判可以独立审视
