## Context

MCP Hub 作为代理网关，在上游（LLM / Dashboard UI）和下游（MCP Server）之间转发 tool call。当前 `MCPConnection.callTool()` 直接将 `arguments` 透传给下游，不做任何类型处理。

上游传来的参数类型经常与下游 schema 不匹配：
- UI 表单将所有输入序列化为 string（如 `issue_number: "123"`）
- LLM 生成的 JSON 中数字/布尔值也可能被包在引号里

下游 MCP Server（如 GitHub Server）对 inputSchema 做严格校验，类型不匹配直接抛 `-32603 Invalid input`。

`MCPConnection` 的 `this.tools` 已经缓存了每个 tool 的完整 `inputSchema`，可直接用于类型推断。

## Goals / Non-Goals

**Goals:**
- 在 `callTool()` 转发前，根据 `inputSchema` 自动修正参数类型
- 只做确定性的无损转换，不改变参数语义
- 记录 debug 日志保证可观测性
- 对上下游完全透明，无需修改任何其他模块

**Non-Goals:**
- 不做完整的 JSON Schema 校验（不校验 required、enum、pattern 等）
- 不处理嵌套 object 的深层属性类型（仅处理 `properties` 一层）
- 不修改 UI 端的表单提交逻辑
- 不新增 API 端点或配置项

## Decisions

### 1. 放在 MCPConnection.callTool() 而非 mcp/server.js 或 api/servers.js

**选择**: `MCPConnection.callTool()`（统一出口）

**理由**: 无论请求从哪条路径进来（HTTP API `/api/servers/tools`、MCP 协议 `/mcp`），最终都经过 `callTool()`。在这里做一次转换，覆盖所有入口，避免重复逻辑。

**备选方案**:
- `mcp/server.js` handler：只覆盖 MCP 协议入口，HTTP API 入口漏掉
- `api/servers.js` handler：只覆盖 HTTP API 入口，MCP 协议入口漏掉
- 两处都加：重复代码，维护负担

### 2. 只处理 properties 第一层，不递归嵌套

**选择**: 仅遍历 `inputSchema.properties` 的顶层 key

**理由**: 绝大多数 MCP tool 的参数是扁平的（`issue_number`、`owner`、`repo`）。嵌套 object 的类型不匹配极为罕见（嵌套通常由 LLM 自行构造 JSON），而递归处理增加复杂度和出错风险。

### 3. 转换策略：只做无损确定性转换

| Schema Type | 输入值 | 转换 | 条件 |
|---|---|---|---|
| `number` | `"123"` / `"3.14"` | `Number(value)` | `!isNaN(Number(value))` 且 value 不是空串 |
| `integer` | `"123"` | `Number(value)` | `Number.isInteger(Number(value))` 且 value 不是空串 |
| `boolean` | `"true"` / `"false"` | `true` / `false` | 严格匹配这两个字符串（小写） |
| `array` | `"[1,2]"` | `JSON.parse(value)` | parse 成功且结果 `Array.isArray` |
| `object` | `'{"a":1}'` | `JSON.parse(value)` | parse 成功且结果是普通对象 |
| 其他 | 任意 | 不转换 | — |

**关键约束**:
- 输入值必须是 `string` 类型才尝试转换（已经是目标类型则跳过）
- 转换失败（如 `Number("abc")` → `NaN`）则保留原值，让下游报错
- 空字符串 `""` 不转换为 `0` 或 `false`，语义模糊

### 4. 日志策略

使用现有的 `logger` 模块，`debug` 级别记录每次实际发生的转换：

```
[MCPConnection] coerce: tool=get_issue, param=issue_number: "123" → 123 (string→number)
```

不记录"没有转换"的参数，避免日志噪音。

## Risks / Trade-offs

- **[Risk] 隐性行为改变** → 通过 debug 日志保证可观测性。如果用户发现意外行为，可以通过日志定位
- **[Risk] 破坏 WAF1 检测逻辑** → 无风险。WAF1 作为 Express 中间件在 `callTool` 之前执行，检测的是原始参数。coerce 发生在 WAF1 之后
- **[Risk] schema 中无 properties 或无 type** → 安全降级：找不到 schema 信息就不转换，原样透传
- **[Trade-off] 不递归嵌套** → 极端场景可能遗漏深层类型不匹配，但覆盖 99% 的实际用例，避免过度工程
