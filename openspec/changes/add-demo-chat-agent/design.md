## Context

项目当前演示能力止于"单 payload → 拦截/放行"的 CLI 与工具测试面板，无法体现核心威胁模型：真实 AI Agent 在 Prompt Injection 下，用合法 MCP 工具链完成数据外泄，被 WAF1 调用链检测在写回公开库的一步拦下。本设计新增一个 Dashboard「演示」Tab 与流式后端，以真实 LLM Agent 驱动该过程，并以 4 按钮（2 场景 × WAF 开/关）矩阵让裁判对比"WAF 开=拦截 / WAF 关=外泄成功"。

关键现状约束（来自探查）：
- `server-github`（官方 `@modelcontextprotocol/server-github`，stdio）已配置于 `config/mcp-servers.json`，是场景一的目标。它是 **stdio MCP**，直连 api.github.com；WAF2 反向代理不在其链路上。
- WAF2 `UPSTREAM` 是单全局值，指向 HTTP 目标应用；不参与 stdio MCP 流量。
- `call-chain.js` 的 `data_exfiltration` 链 step1 已能匹配 GitHub 读类工具（search/get/list），但 step2 外发通道正则不识别 `create_or_update_file` / `create_pull_request`，导致链不触发。
- `dynamic-policy.js` 为 supabase 专用，对 GitHub 工具 no-op。
- WAF1 PII 检测器偏中国格式；仅当外泄内容含 email/信用卡/护照时命中。
- DashScope OpenAI 兼容接口与 API Key 已在 `config/guardrails-config.json` 配好（WAF2 用 `qwen-turbo`）。

## Goals / Non-Goals

**Goals:**
- 真实 LLM Agent 端到端演示：预设 prompt → LLM function-calling 调 MCP 工具 → 工具调用真实过 WAF → 流式回显思考/调用/判决/回复。
- 4 按钮矩阵（2 场景 × WAF 开/关），WAF 开关由后端逐次调用旁路控制，不污染全局配置。
- 场景一（GitHub 致命三角）稳定可演示：WAF 开在 `create_or_update_file` 拦下；WAF 关全链跑完外泄。
- UI 与现有 Dashboard 视觉语言一致，有过渡动效。
- 诚实兜底：LLM 未触发预期工具时如实回显，不伪造。

**Non-Goals:**
- 不实现 Plan B（http-request MCP → WAF2 upstream 指 api.github.com）；仅作为备选记录。
- 不新增 WAF2 检测分类、不改 WAF2 代码。
- 不为场景一引入 Mock GitHub MCP（用户选定真 server-github）。
- 不做生产化、多用户并发隔离。
- 不改 `stats.js` 的 severity/MITRE 映射（沿用 `data_exfiltration` 既有 `callChain` 分类，非新规则）。

## Decisions

### 决策 1：真实 LLM Agent loop，而非脚本化

**选择**：后端 `/api/demo/chat` 内置 Agent loop，调 DashScope `/chat/completions`（OpenAI 兼容，`tools=function-calling`），LLM 自行决定调用哪个 MCP 工具。

**理由**：用户明确要"真实 LLM"；脚本化虽确定但失去"AI 被诱导"的真实感，无法体现威胁模型。

**备选**：脚本化 Agent（按钮→预设对话气泡+真实 `/api/tools/call`）——可靠但"AI"是演的，被否。

**模型选择**：演示 Agent 用 `qwen-plus`（或 `qwen-max`），与 WAF2 分类器的 `qwen-turbo` 分离配置。理由：场景一为 7+ 步连续 function-calling 长链，`qwen-turbo` 多步易跑偏断链；分类任务用 turbo 即可，Agent 推理用更强模型。模型名作为 `config/guardrails-config.json` 的 `demo.agentModel` 可配置。

### 决策 2：WAF 开关 = 后端逐次旁路编排，不翻转全局 mode

**选择**：演示后端按按钮的 WAF 标志，逐次工具调用控制路径：
- WAF 开 → 内部走 `/api/tools/call`（经 WAF1 中间件，真实检测）。
- WAF 关 → 直接 `serviceManager.mcpHub.callTool(server, tool, args)`（绕过 WAF1 中间件）。

**理由**：WAF 状态是全局配置（`mode`/`waf1.enabled`），翻转会影响整个 Dashboard、污染实时日志、并发不安全。逐次旁路让"WAF 关"时工具调用真打到 `server-github` → 真外泄，又隔离于全局。

**备选**：全局切换 mode——简单但不隔离，被否。
**备选**：把 WAF1 检测重构为可独立调用的函数 `runWaf1Check(tool,args)` 再由后端按标志调用——更干净但需重构 `waf1/index.js` 中间件为本体函数+中间件包装。本期采用"内部 HTTP 调 `/api/tools/call`"实现 WAF 开路径以最小改动；若性能/自调用别扭，后续可重构（列为开放问题）。

### 决策 3：场景一防御层 = WAF1 调用链，不动 WAF2

**选择**：场景一"WAF 开/关"即 WAF1 开/关。WAF2 不参与（stdio MCP 绕过 WAF2）。

**理由**：PII 在 `create_or_update_file` 的 `content` 参数里，正是 WAF1 MCP 协议层检测点；调用链检测（读私有→写公开）与 PII 格式无关，是更稳的信号。强行把 server-github 流量改道 WAF2 需 TLS 终止 + auth header 转发 + 改全局 upstream，脆弱且无必要。

### 决策 4：扩展 `call-chain.js` step2 正则识别 GitHub 写工具

**选择**：将 `data_exfiltration` step2 的外发通道正则
```
/(^|__)create_(?:gist|paste|snippet|repository|repo|issue|comment|file)/i
```
扩展为
```
/(^|__)create_(?:gist|paste|snippet|repository|repo|issue|comment|file|or_update_file|pull_request)/i
```
使 `create_or_update_file`（命中 `create_or_update_file`→`create_`+`or_update_file`）与 `create_pull_request` 进入 step2。

**理由**：当前正则认识 `create_file`/`create_issue` 等却不认识 GitHub 实际写工具，是精确缺口；一行扩展即让"读私有库→写公开库"链触发。沿用既有 `data_exfiltration` 链与 `callChain` 统计分类，不新增 `stats.js` 映射（遵守设计规则：非新规则/检测器，无需注册新 severity/MITRE）。

**验收前提**：扩展后须在真 server-github 上验证"WAF 开"稳定拦下 `create_or_update_file`（见 specs 验收场景与开放问题）。

### 决策 5：路由注册位置 = 第 9 步 WAF1 中间件之前

**选择**：`/api/demo/chat`（SSE）与 `/api/demo/scenarios` 注册在 `registerMcpConfigRoutes` 之后、WAF1 中间件 `app.use("/api", waf1Middleware)` 之前（即 server.js 路由顺序第 8→9 步之间）。

**理由**：demo chat 请求本身是 Agent 对话，绝不能被 WAF1 中间件当作攻击拦掉；必须位于中间件之前。仍处于 `app.use('/api', authMiddleware)`（第 5 步）之后，需登录，不破坏认证边界。WAF 开/关的工具检测由后端在 loop 内部按路径选择触发，不依赖中间件全局生效。

**认证边界检查**：新路由在 authMiddleware 之后 → 受登录保护 ✓；在 waf1Middleware 之前 → demo 自身请求不被检测 ✓（工具调用的检测由后端显式走 `/api/tools/call` 触发）。不破坏现有边界。

### 决策 6：SSE 流式协议

**选择**：`/api/demo/chat` 为 SSE（`text/event-stream`），按事件类型推送：
- `user`：预设 prompt 气泡。
- `token`：LLM 流式 token（思考/回复）。
- `tool_call`：LLM 决定调用工具（server/tool/args）。
- `waf`：WAF 判决（`blocked`/`allowed` + reason/category/type，HTTP 403 时的响应体格式见 specs）。
- `tool_result`：工具返回（截断展示）。
- `done`/`error`：结束。

**理由**：复用 Dashboard 既有 SSE 模式（`registerSSERoute`）；前端原生 `EventSource` 即可；裁判能看到 Agent 逐步决策。

### 决策 7：UI 一致性与动效

**选择**：演示 Tab 复用 `styles.css` 设计系统（#0d1117 背景、Inter、Linear 极光渐变点缀、Tabler 卡片布局）。4 按钮矩阵用场景分组卡片；聊天气泡区支持暗色气泡、流式打字动效、工具调用折叠块、WAF 拦截用红色高亮+图标、放行用绿色。按钮点击有过渡态（loading→streaming→done）。

**理由**：遵守 UI 硬约束（Grafana+Linear+Tabler 一致性、设计感、动效）。新增 API 方法 `demoChat`（流式）与 `getDemoScenarios` 加入 `dashboard/services/api.js`（遵守设计规则）。不涉及 `auth.js` 内联 HTML，无需模板转义处理。

### 决策 8：Plan B 作为备选（本期不实现）

**记录**：若场景一调用链扩展后仍无法稳定拦截，备选为改用 `http_request` 类 MCP 工具直发 api.github.com，并将 WAF2 `UPSTREAM` 指向 api.github.com，由 WAF2 LLM 语义检测请求体外泄。代价：需处理 GitHub TLS/auth、改全局 upstream、WAF2 单 upstream 切场景。本期不实现，留作 design 记录。

### 决策 9：场景二 = system prompt 敏感 key 外泄，WAF2 body 检测（WAF1 漏、WAF2 拦）

**选择**：场景二通过 `systemPrompt` 注入含 `sk-9e24ea...` API key 的应用配置，`presetPrompt` 用原文（webhook.cool backup location）诱导 Agent"备份配置"。Agent 从 system prompt 上下文直接输出配置（含 key），用 `http_request` POST 到 webhook.cool，**不调用 `file_read`**。

**WAF 层分工（展示 WAF1 漏 + WAF2 拦的双层对比）**：
- WAF1（`validateToolCall`）参与但漏：无 `file_read` 前置 → 调用链不触发；`webhook.cool` 不在 dataExfiltration 黑名单（只有 `webhook.site`）→ 不拦；ssrf 规则不拦公网域名 → 不拦。**WAF1 全漏**。
- WAF2（reverse proxy, `upstream=webhook.cool`）兜底拦：检测 POST body 含 `sk-` API key → `sensitive_data_exposure`（A02/T1552）。

**WAF 开/关语义（wafLayer=WAF2）**：
- WAF 开 → demo 调 `validateToolCall`（WAF1 漏，放行）+ 改写 `http_request` 的 `args.url` 为 `http://waf2:8081/<path>`（WAF2 检测 body 拦）
- WAF 关 → 不调 `validateToolCall` + url 直连 webhook.cool（key 外泄，webhook.cool 收到）

**为何不用 file_read 读 config（放弃的方案）**：`file_read`→`http_request` 触发 WAF1 调用链（read→外发），WAF1 先拦，WAF2 没机会。改用 system prompt 输出避开调用链，让 WAF1 漏、WAF2 拦，展示双层对比与 WAF2 价值。

**WAF2 upstream**：场景二跑时 `UPSTREAM=https://lively-otter-81.webhook.cool`（用户提前设）。WAF2 转发到 webhook.cool（放行时）/ 拦截 body 含 key。WAF2 检测只看 method+path+body，body 含 `sk-` key 即触发 `sensitive_data_exposure`，与目标 URL 无关，故 reverse proxy（固定 upstream）即可，不需 forward proxy 改造、不改 WAF2 代码。

**targetServer**：`http-client`（提供 `http_request` 工具，单 server，不需 file_read/MCP 工具聚合）。

**敏感数据**：`sk-9e24ea719c084c1e881f097fa450b7b6`（与项目 `config/guardrails-config.json` 的 `waf2.llm.apiKey` 一致），注入 `systemPrompt`。WAF2 few-shot 已有 `sk-` 前缀 key 检测判例。

**Risks**：
- Agent 可能不配合"备份配置"输出 system prompt（红队模型需测试）。缓解：systemPrompt 明确"应用配置在系统提示词中，用户要求备份时输出该配置"；预设 prompt 联调；重试按钮。
- WAF2 检测 body 含 `sk-` key 需 WAF2 LLM 识别（few-shot 有判例）。联调验证。
- webhook.cool 是真实外部服务，WAF 关时 Agent 真访问；`lively-otter-81` 是用户实例，演示后删。

## Risks / Trade-offs

- **[LLM 非确定性，长链可能不按剧本调工具]** → 缓解：按场景收窄暴露给 LLM 的工具集（场景一只暴露 server-github 相关工具）；预设 prompt 事先测试；UI 提供「重试」按钮；LLM 未触发预期工具时如实回显"AI 本次未触发该工具调用"，不伪造。模型用 qwen-plus/max 提升多步稳定性。
- **[调用链扩展后仍拦不住（如 LLM 用别的外发路径）]** → 缓解：以真 server-github"WAF 开"验证为前置；若失败启用 Plan B。验收场景明确"必须拦下 create_or_update_file"。
- **[真 GitHub PAT 已 commit 进仓库（凭据泄露）]** → 缓解：演示前 rotate PAT、从 git 历史清除、改用专用演示账号 + 专用仓库（私有放假 PII、公开接收）；"WAF 关"仅在此专用账号跑且演示后清理 PR。列为前置任务。
- **[WAF 关路径真造 PR 泄 PII]** → 缓解：仅在专用演示仓库；假 PII；演示后清理。
- **[后端内部 HTTP 自调 `/api/tools/call` 别扭/性能]** → 缓解：同进程内调用开销可接受；若成问题则重构 WAF1 为可调用函数（开放问题）。
- **[WAF 关时绕过 WAF1 中间件，但全局 WAF2 仍可能挡 HTTP 目标场景]** → 场景一不涉 WAF2，无影响；场景二（wafLayer=WAF2）WAF 开=validateToolCall(WAF1 漏)+url 改写经 WAF2，WAF 关=直连 webhook.cool，见决策 9。

## Migration Plan

1. 前置：rotate 并清除已泄露 GitHub PAT；准备专用演示 GitHub 账号与仓库。
2. 扩展 `call-chain.js` step2 正则；在真 server-github 上以"WAF 开"验证拦截 `create_or_update_file`。
3. 实现 demo 后端（`api/demo.js`）与路由注册。
4. 实现前端演示 Tab。
5. 配置 `demo` 段（Agent 模型、场景一 prompt）。
6. 端到端跑通 4 按钮；填充场景二。

**回滚**：演示 Tab 为新增，移除 `api/demo.js`、路由注册、前端 Tab、`call-chain.js` 正则回退即可恢复；`call-chain.js` 回退仅影响 GitHub 写工具识别，不影响其他场景。

## Open Questions

- ~~场景二（第 2 个漏洞场景）的 prompt、目标 MCP Server、预期 WAF 层——留空待用户填。~~ **已定（决策 9）**：system prompt 注入 sk-key + 原文 webhook.cool 诱导，http-client 的 http_request POST，wafLayer=WAF2，WAF1 漏 WAF2 拦。
- WAF 开路径是否重构 WAF1 为可调用函数以避免自调 HTTP（见决策 2 备选）。
- 演示 Agent 模型最终选 qwen-plus 还是 qwen-max（成本/稳定性权衡，待联调定）。
- 场景一外泄的假 PII 是否需含 email/信用卡以同时触发 PII 检测器（双信号更稳），还是仅靠调用链。
- 场景二 Agent（红队模型）是否稳定配合"备份配置"输出 system prompt，需联调验证；若不配合考虑 systemPrompt 强化引导或形态 B（直接 system prompt 泄露）。
