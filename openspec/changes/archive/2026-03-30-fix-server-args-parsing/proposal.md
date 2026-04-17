## Why

Dashboard UI 保存 MCP Server 配置时，args 字段用逗号分割（`split(',')`），但用户新建 server 时习惯用空格分隔参数（如 `-y @modelcontextprotocol/server-filesystem /home/q1n9`）。空格分隔的输入不会被正确拆分，导致整个字符串变成数组中的一个元素，下游 npx 收到错误的参数。

编辑已有 server 时往返一致（逗号进逗号出），但新建时用户直觉与实际行为不匹配。

## What Changes

- 修改 Dashboard `app.js` 中 server 配置保存逻辑的 args 解析方式
- 最终方案：改为要求输入 JSON 数组（如 `["-y", "@modelcontextprotocol/server-filesystem", "/home/q1n9"]`），保存时 `JSON.parse` 校验，避免空格/逗号分割的歧义

## Capabilities

### New Capabilities

（无）

### Modified Capabilities

- `config`: server 配置 args 字段的解析方式变更

## Impact

- **代码**: `mcp-hub/src/dashboard/app.js` — 保存时改为 JSON 数组解析，加载时以格式化 JSON 回显
- **UI**: `mcp-hub/src/dashboard/index.html` — `args`/`env`/`headers` 输入区已使用 `textarea` 承载 JSON 文本
- **其他模块**: 无影响
