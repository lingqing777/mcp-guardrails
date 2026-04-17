## Why

UI 和 LLM 上游经常将所有 tool call 参数序列化为字符串（如 `issue_number: "123"`），而下游 MCP Server 的 inputSchema 要求特定类型（如 `number`）。MCP Hub 作为代理网关，目前原样透传参数，导致类型不匹配时下游直接报错（`Invalid input: expected number, received string`）。用户无法修改第三方 MCP Server，这类问题应由代理层透明处理。

## What Changes

- 在 `MCPConnection.callTool()` 转发请求前，新增参数类型强转逻辑
- 根据 tool 已缓存的 `inputSchema` 对 arguments 做无损类型转换：
  - `string → number`（仅当字符串是合法数字时）
  - `string → boolean`（仅 `"true"` / `"false"`）
  - `string → integer`（仅当字符串是合法整数时）
  - `string → array/object`（尝试 JSON.parse，失败则保持原样）
- 转换不了的参数原样保留，让下游给出明确报错
- 每次转换记录 debug 日志，保证可观测性

## Capabilities

### New Capabilities

（无新增独立能力）

### Modified Capabilities

- `mcp-proxy`: 新增工具调用参数自动类型强转需求，在代理转发前根据 inputSchema 做无损类型转换

## Impact

- **代码**: `mcp-hub/src/MCPConnection.js` — `callTool()` 方法，新增 coerce 逻辑
- **WAF1/WAF2**: 无影响 — 强转发生在 WAF1 检测之后、实际 MCP 请求之前；WAF2 位于 HTTP 层，不涉及
- **Docker/docker-compose.yml**: 无影响
- **路由注册顺序**: 无影响 — 不涉及新路由
- **Dashboard 5 秒刷新**: 无影响
- **依赖**: 无新增依赖
