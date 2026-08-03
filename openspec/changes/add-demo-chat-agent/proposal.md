## Why

现有演示手段是 CLI 脚本（`demo/test_guardrails.py`）和 Dashboard 工具测试面板——两者都是"直接发一个 payload 看拦截结果"，无法展示项目真正的威胁模型：**真实 AI Agent 被 Prompt Injection 诱导，用合法 MCP 工具链把敏感数据外泄，被双层 WAF 在调用链上拦下**。面向信安作品赛裁判演示，需要一个端到端、可视化、可复现的"真实 LLM Agent + WAF 对比"聊天界面，让裁判一眼看清"WAF 开/关"的差异。

## What Changes

- 新增 Dashboard「演示」Tab：4 按钮矩阵 = 2 漏洞场景 × WAF 开/关；聊天气泡区以 SSE 流式展示真实 LLM 的思考、工具调用、WAF 判决与最终回复。
- 新增 SSE 流式后端端点 `/api/demo/chat`：内置真实 LLM Agent loop（复用 WAF2 已配置的 DashScope OpenAI 兼容接口，演示 Agent 用 qwen-plus/max，与 WAF2 分类器的 qwen-turbo 分离），通过 function-calling 调用场景对应的 MCP 工具，工具调用经 `/api/tools/call` 真实过 WAF1。
- 新增后端旁路编排逻辑：按按钮的 WAF 开/标志，**逐次调用**控制是否过 WAF1（WAF 开 → 走 `/api/tools/call` 经 WAF1 中间件；WAF 关 → 直接 `MCPHub.callTool()` 绕过中间件），**不翻转全局 mode、不污染全局配置、不触碰 WAF2 upstream 环境变量**。
- 扩展 WAF1 调用链检测（`call-chain.js` 的 `data_exfiltration` step2）：让外发通道正则识别 GitHub 的 `create_or_update_file` / `create_pull_request`，使"读私有库 → 写公开库"的致命三角链能被稳定触发拦截。这是 GitHub 场景"WAF 开"能拦下的关键依赖。
- 预置真实 `server-github`（已存在于 `config/mcp-servers.json`）作为场景一的目标 MCP Server；场景二留空槽位待填。
- **BREAKING**：无。所有新增均为可选 Tab 与新端点，不影响现有 6 Tab 与 `/api/tools/call` 行为。

## Capabilities

### New Capabilities
- `demo-chat-agent`: 真实 LLM Agent 演示聊天界面与流式后端编排，含 4 按钮（2 场景 × WAF 开/关）矩阵、Agent loop、WAF 旁路控制、诚实兜底（LLM 未触发预期工具时如实回显）。

### Modified Capabilities
- `dashboard`: 新增「演示」Tab，复用现有 Grafana+Linear+Tabler 设计语言与 SSE 机制；新增 `services/api.js` 中 `demoChat` 流式方法。
- `waf1`: `call-chain.js` 的 `data_exfiltration` 外发通道识别扩展 GitHub 写工具，使调用链检测覆盖 GitHub MCP 致命三角场景（spec 级行为：新增可识别的外发工具名）。

## Impact

- **WAF1/WAF2 双层架构影响**
  - WAF1：扩展 `call-chain.js` step2 正则（一处），不改动 5 阶段流水线结构、不新增检测器、不改动 `stats.js` 的 severity/MITRE 映射（沿用 `data_exfiltration` 既有分类）。
  - WAF2：**不参与**演示场景一。GitHub `server-github` 为 stdio MCP，直连 api.github.com，WAF2 反向代理不在其链路上；演示"WAF 开/关"对场景一即 WAF1 开/关。WAF2 仍按现有配置保护 HTTP 目标应用，不受影响。
- **Docker / docker-compose.yml**：无需修改。不调整 WAF2 `UPSTREAM` 环境变量（场景一不依赖 WAF2）。Plan B（http-request MCP → WAF2 upstream 指 api.github.com）作为 design.md 备选方案记录，本期不实现。
- **路由注册顺序（server.js）**：新增 `/api/demo/chat`（SSE）与 `/api/demo/scenarios`（场景元信息）。两者均需登录但**自身的 chat 请求不能被 WAF1 中间件拦掉**，因此插入位置 = **第 9 步 WAF1 中间件之前**（与 `/api/config`、`/api/waf1/*`、`/api/mcp-config/*` 同属"WAF1 中间件之前注册"的区间），紧随 `registerMcpConfigRoutes` 之后。
- **Dashboard 5 秒刷新**：演示 Tab 不纳入 5 秒轮询。聊天流式靠 SSE 推送；WAF 判决可同时点亮既有「检测记录」/「态势感知」实时日志（复用现有 SSE），不引入新高频接口。
- **依赖与凭据**：复用 `config/guardrails-config.json` 中已有的 DashScope API Key；演示 Agent 模型名新增为可配置项（默认 `qwen-plus`）。`config/mcp-servers.json` 中已 commit 的真实 GitHub PAT 为安全隐患，演示前须 rotate 并从 git 历史清除（记为前置任务，非本 change 代码改动）。
- **代码**
  - `mcp-hub/src/api/demo.js`（新增）— 演示后端：Agent loop、SSE 流、旁路编排。
  - `mcp-hub/src/api/index.js` — 注册 `registerDemoRoutes`。
  - `mcp-hub/src/server.js` — 在第 9 步之前注册 demo 路由。
  - `mcp-hub/src/waf1/call-chain.js` — step2 正则扩展。
  - `mcp-hub/src/dashboard/` — 新增演示 Tab（index.html / app.js / styles.css / services/api.js）。
  - `config/guardrails-config.json` — 新增 `demo` 配置段（Agent 模型、场景定义、预设 prompt）。
