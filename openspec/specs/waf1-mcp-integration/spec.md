# waf1-mcp-integration Specification

## Purpose
TBD - created by archiving change fix-mcp-endpoint-waf1-bypass. Update Purpose after archive.
## Requirements
### Requirement: validateToolCall 纯函数

层级：WAF1

`waf1/index.js` SHALL 导出 `validateToolCall(tool, args, context)` 函数，执行完整的 5 阶段检测管线（限流 → RBAC → 白名单 → 正则规则 → 检测器），返回检测结果对象。

- 输入：`tool` (string)、`args` (object)、`context` (object, 含 `clientId`/`userId`)
- 输出：`{ allowed: true }` 或 `{ allowed: false, status: number, error: object }`
- 此函数 SHALL NOT 依赖 Express `req`/`res` 对象
- 此函数 SHALL 在 `waf1Enabled === false` 时直接返回 `{ allowed: true }`

#### Scenario: WAF1 启用时检测到 SQL 注入
- **WHEN** `validateToolCall("read_file", { path: "'; DROP TABLE users--" }, { clientId: "c1", userId: "agent" })` 被调用
- **THEN** 返回 `{ allowed: false, status: 403, error: { error: "WAF1 拦截", reason: "...", type: "RULE_BLOCKED", category: "sqlInjection" } }`

#### Scenario: WAF1 启用时正常参数通过
- **WHEN** `validateToolCall("read_file", { path: "/home/user/readme.txt" }, { clientId: "c1", userId: "agent" })` 被调用
- **THEN** 返回 `{ allowed: true }`

#### Scenario: WAF1 关闭时直接放行
- **WHEN** WAF1 处于 disabled 状态且调用 `validateToolCall(...)`
- **THEN** 返回 `{ allowed: true }`，不执行任何检测

### Requirement: waf1Middleware 复用 validateToolCall

层级：WAF1

现有 `waf1Middleware(req, res, next)` SHALL 改为内部调用 `validateToolCall()`，根据返回值决定 `res.status().json()` 或 `next()`。对外行为（HTTP 状态码、响应 body 结构）SHALL 保持完全不变。

#### Scenario: Dashboard API 拦截行为不变
- **WHEN** Dashboard 通过 POST `/api/tools/call` 发送含 SQL 注入的请求
- **THEN** 响应 SHALL 与重构前完全一致：HTTP 403 + `{ error: "WAF1 拦截", reason, type, category }`

#### Scenario: 非保护路由直接放行
- **WHEN** 请求路径不在 protectedRoutes 列表中
- **THEN** `waf1Middleware` SHALL 直接调用 `next()`，不调用 `validateToolCall()`

### Requirement: MCP 协议工具调用经过 WAF1 检测

层级：MCP Hub

`mcp/server.js` 中 `setRequestHandler(CallToolRequestSchema, handler)` 内，在调用 `mcpHub.rawRequest()` 之前，SHALL 调用 `validateToolCall()` 对工具名和参数进行检测。

- 仅对 `tools` 类型的 capability 调用检测（不检测 resources/prompts）
- `context.clientId` 取自 `extra.sessionId` 或降级为 `'mcp-client'`
- 拦截时 SHALL 抛出 `McpError(ErrorCode.InvalidParams, reason)`
- SHALL 尊重 `isWaf1Enabled()` 开关

#### Scenario: MCP Agent 发送含路径穿越的工具调用被拦截
- **WHEN** MCP Agent 调用 `filesystem__read_file({ path: "../../../etc/passwd" })`
- **THEN** WAF1 检测到 pathTraversal，MCP handler 抛出 `McpError`
- **AND** Agent 收到 JSON-RPC error 响应
- **AND** stats 中记录一条 WAF1 拦截

#### Scenario: MCP Agent 正常工具调用通过
- **WHEN** MCP Agent 调用 `filesystem__read_file({ path: "/home/q1n9/readme.txt" })`
- **THEN** `validateToolCall` 返回 `{ allowed: true }`
- **AND** 请求正常转发到后端 MCP Server

#### Scenario: Lite 模式下 MCP 工具调用跳过 WAF1
- **WHEN** 系统运行在 Lite 模式（WAF1 disabled）
- **THEN** MCP 工具调用 SHALL 跳过 `validateToolCall()`，直接转发

