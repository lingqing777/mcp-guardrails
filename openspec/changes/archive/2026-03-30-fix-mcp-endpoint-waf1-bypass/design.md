## Context

WAF1 检测管线（限流 → RBAC → 白名单 → 正则规则 → 检测器）当前实现为 Express 中间件 `waf1Middleware(req, res, next)`，通过 `req.body` 提取工具名和参数，通过 `res.status(403).json()` 返回拦截结果。

MCP 协议端点 `/mcp` 使用 SSE + JSON-RPC 传输。工具调用在 `MCPServerEndpoint.setupRequestHandlers()` 内的 `setRequestHandler(CallToolRequestSchema, handler)` 中处理，数据结构为 `request.params = { name, arguments }`。

两条路径的检测输入本质相同（工具名 + 参数对象），但协议层和响应格式不同。

## Goals / Non-Goals

**Goals:**
- 使 MCP 协议路径的工具调用经过与 REST API 路径完全相同的 WAF1 检测管线
- 保持现有 Dashboard API 行为不变
- 共用同一套 stats 统计、日志、规则配置
- 尊重 Full/Lite 模式开关（`isWaf1Enabled()`）
- MCP 路径拦截时返回协议规范的 `McpError(ErrorCode.InvalidParams, reason)`

**Non-Goals:**
- 不实现工具类型感知的差异化规则（如数据库工具放宽 SQL 检测）——留给后续迭代
- 不在 `/mcp` 端点添加认证机制
- 不修改 WAF2、Dashboard 前端或配置文件格式
- 不改变调用链追踪的 session 模型

## Decisions

### Decision 1: 抽出 `validateToolCall()` 纯函数

从 `waf1Middleware` 中提取检测逻辑为：

```javascript
export function validateToolCall(tool, args, context = {}) {
  // context: { clientId, userId } — 用于限流和 RBAC
  // 返回: { allowed: true } 或 { allowed: false, status, error }
  // error 结构: { error, reason, type, category, ... }
}
```

此函数不依赖 Express `req/res`，5 个检测阶段（限流、RBAC、白名单、正则、检测器）全部在内部执行。

`waf1Middleware` 改为调用 `validateToolCall()`，将返回值映射为 HTTP 响应。保持对外行为完全不变。

### Decision 2: MCP handler 中调用 validateToolCall

在 `mcp/server.js` 的 `setRequestHandler(callSchema)` 内，`rawRequest` 之前调用：

```javascript
if (isWaf1Enabled() && capType.id === 'tools') {
    const result = validateToolCall(originalName, request.params.arguments, {
        clientId: extra?.sessionId || 'mcp-client',
        userId: 'mcp-agent'
    });
    if (!result.allowed) {
        throw new McpError(ErrorCode.InvalidParams, result.error.reason || 'WAF1 拦截');
    }
}
```

仅对 `tools` 类型的 capability 做检测（不检测 resources/prompts listing）。

### Decision 3: context 参数设计

MCP 路径没有 HTTP headers/session，`context` 使用：
- `clientId`: SSE 的 `sessionId`（由 `extra` 提供），用于限流
- `userId`: 固定 `'mcp-agent'`，RBAC 按此身份检查

## Risks / Trade-offs

| 风险 | 应对 |
|------|------|
| MCP 路径限流标识较粗（同一 Agent 共享 sessionId） | 可接受，当前 Dashboard 也是按 IP 限流 |
| 正则规则对 MCP 工具可能误报 | 当前配置的 filesystem/rest-api 不会触发误报；后续可加工具白名单 |
| `validateToolCall` 是同步函数，检测器中无异步操作 | 当前所有检测器均为同步，无需改为 async |
