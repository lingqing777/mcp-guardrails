## Why

MCP Guardrails 的 WAF1 防护层当前仅覆盖 Dashboard REST API 路径 (`/api/tools/call`)，而真正的 Agent 连接入口 `/mcp`（SSE + JSON-RPC）完全绕过 WAF1 检测。

这意味着在实际部署中（OpenClaw、Claude Desktop 等 Agent 通过 MCP 协议连接），WAF1 的全部检测能力（正则规则、检测器、RBAC、限流、调用链追踪）形同虚设。产品核心卖点"MCP 协议层防护"无法兑现。

## What Changes

将 WAF1 的检测逻辑从 Express 中间件中抽离为协议无关的纯函数 `validateToolCall()`，在 MCP 协议工具调用处理器中调用，使两条路径共享同一套检测引擎。

- `/api/tools/call`（Dashboard）：保持现有 Express 中间件不变，内部改为调用 `validateToolCall()`
- `/mcp`（Agent MCP 协议）：在 `setRequestHandler(CallToolRequestSchema)` 内调用 `validateToolCall()`，拦截时返回 `McpError`

## Capabilities

### Modified Capabilities
- `dashboard`: 态势感知面板展示的 WAF1 统计数据将包含来自 MCP 协议路径的拦截记录（无需改代码，因为共用同一个 stats 收集器）

### New Capabilities
- `waf1-mcp-integration`: WAF1 检测逻辑与 MCP 协议工具调用处理器的集成

## Impact

- `mcp-hub/src/waf1/index.js` — 抽出 `validateToolCall()` 纯函数，`waf1Middleware` 改为调用它
- `mcp-hub/src/mcp/server.js` — 在 `callSchema` handler 中调用 `validateToolCall()`
- 不涉及：WAF2、Dashboard 前端、配置文件、Docker
