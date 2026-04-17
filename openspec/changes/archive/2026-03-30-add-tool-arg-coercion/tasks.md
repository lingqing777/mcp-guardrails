## 1. 核心实现

- [x] 1.1 在 `mcp-hub/src/MCPConnection.js` 中实现 `coerceArgs(tool, args)` 方法：遍历 `tool.inputSchema.properties`，根据 `type` 字段对 `args` 中对应 key 做无损类型转换（string→number/integer/boolean/array/object）。无 schema 或转换失败时原样返回。
- [x] 1.2 在 `callTool()` 方法中（约 line 476，`this.client.request` 调用前），调用 `coerceArgs(tool, args)` 获取转换后的参数，替换原始 `args` 传给下游。

## 2. 日志

- [x] 2.1 在 `coerceArgs()` 中，每次实际发生转换时通过 `logger.debug()` 记录：tool 名称、参数名、原始值、转换后值、类型变化。格式：`[MCPConnection] coerce: tool=<name>, param=<key>: <old> → <new> (string→<type>)`

## 3. 验证

- [x] 3.1 启动 MCP Hub，连接一个有 number 类型参数的 MCP Server（如 GitHub Server），通过 Dashboard UI 传入字符串参数，确认调用成功且日志中有 coerce 记录
