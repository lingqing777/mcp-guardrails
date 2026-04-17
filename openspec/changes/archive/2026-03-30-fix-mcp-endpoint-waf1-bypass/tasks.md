## 1. 抽出 validateToolCall 纯函数

- [x] 1.1 在 `waf1/index.js` 中新增 `export function validateToolCall(tool, args, context = {})` 函数，将 waf1Middleware 的 5 阶段检测逻辑（限流 → RBAC → 白名单 → 正则规则 → 检测器）移入其中，返回 `{ allowed, status?, error? }`
- [x] 1.2 `validateToolCall` 在 `waf1Enabled === false` 时直接返回 `{ allowed: true }`

## 2. 重构 waf1Middleware 调用 validateToolCall

- [x] 2.1 修改 `waf1Middleware` 内部逻辑：保留路由保护检查和参数提取，核心检测改为调用 `validateToolCall(tool || prompt || uri, args, { clientId, userId })`，根据返回值决定 `res.status().json()` 或 `next()`
- [x] 2.2 确保对外行为完全不变（HTTP 状态码、响应 body 结构、日志格式）

## 3. MCP 协议处理器集成 WAF1

- [x] 3.1 在 `mcp/server.js` 顶部 import `validateToolCall` 和 `isWaf1Enabled`
- [x] 3.2 在 `setRequestHandler(callSchema)` 内、`rawRequest` 调用之前，对 tools 类型 capability 调用 `validateToolCall(originalName, request.params.arguments, { clientId: extra?.sessionId, userId: 'mcp-agent' })`
- [x] 3.3 拦截时抛出 `McpError(ErrorCode.InvalidParams, reason)`，并记录日志

## 4. 验证

- [x] 4.1 用 mcporter 发送含攻击 payload 的工具调用，确认 WAF1 拦截并返回 JSON-RPC error
- [x] 4.2 用 mcporter 发送正常工具调用，确认放行
