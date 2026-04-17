## ADDED Requirements

### Requirement: 工具调用参数自动类型强转

层级：MCP Hub — `MCPConnection.callTool()`

系统 MUST 在转发 tool call 到下游 MCP Server 之前，根据 tool 的 `inputSchema.properties` 对参数进行无损类型强转。

强转规则：
- 当 schema type 为 `number` 且参数值为合法数字字符串时，MUST 转换为 `Number`
- 当 schema type 为 `integer` 且参数值为合法整数字符串时，MUST 转换为 `Number`
- 当 schema type 为 `boolean` 且参数值为 `"true"` 或 `"false"` 时，MUST 转换为对应布尔值
- 当 schema type 为 `array` 且参数值为合法 JSON 数组字符串时，MUST 转换为数组
- 当 schema type 为 `object` 且参数值为合法 JSON 对象字符串时，MUST 转换为对象
- 参数值已经是目标类型时，MUST NOT 进行转换
- 转换失败时（如 `"abc"` 转 number），MUST 保留原始值不做修改
- 空字符串 `""` MUST NOT 被转换为 `0`、`false` 或其他值

系统 MUST 仅处理 `inputSchema.properties` 的顶层属性，不递归嵌套对象。

当 tool 无 `inputSchema` 或 `inputSchema` 无 `properties` 时，系统 MUST 原样透传参数。

#### Scenario: string 参数转为 number

- **GIVEN** tool `get_issue` 的 inputSchema 声明 `issue_number` 类型为 `number`
- **WHEN** 上游传入 `{ "issue_number": "123" }`
- **THEN** 系统将参数转换为 `{ "issue_number": 123 }` 后转发给下游 MCP Server

#### Scenario: string 参数转为 boolean

- **GIVEN** tool `set_flag` 的 inputSchema 声明 `enabled` 类型为 `boolean`
- **WHEN** 上游传入 `{ "enabled": "true" }`
- **THEN** 系统将参数转换为 `{ "enabled": true }` 后转发

#### Scenario: 无法转换时保留原值

- **GIVEN** tool `get_issue` 的 inputSchema 声明 `issue_number` 类型为 `number`
- **WHEN** 上游传入 `{ "issue_number": "not-a-number" }`
- **THEN** 系统保留 `{ "issue_number": "not-a-number" }` 原样转发，由下游返回校验错误

#### Scenario: 空字符串不转换

- **GIVEN** tool `get_issue` 的 inputSchema 声明 `issue_number` 类型为 `number`
- **WHEN** 上游传入 `{ "issue_number": "" }`
- **THEN** 系统保留 `{ "issue_number": "" }` 原样转发

#### Scenario: 参数已是正确类型

- **GIVEN** tool `get_issue` 的 inputSchema 声明 `issue_number` 类型为 `number`
- **WHEN** 上游传入 `{ "issue_number": 123 }`
- **THEN** 系统不做任何转换，直接转发

#### Scenario: tool 无 inputSchema

- **GIVEN** tool `legacy_tool` 没有 `inputSchema`
- **WHEN** 上游传入任意参数
- **THEN** 系统原样透传参数

### Requirement: 参数强转日志记录

层级：MCP Hub — `MCPConnection.callTool()`

每次实际发生的参数类型转换 MUST 记录 debug 级别日志，包含 tool 名称、参数名、原始值、转换后值和类型变化。

未发生转换的参数 MUST NOT 记录日志。

#### Scenario: 转换时记录日志

- **GIVEN** tool `get_issue` 的 `issue_number` 从 `"123"` 被转换为 `123`
- **WHEN** 转换完成
- **THEN** 系统记录 debug 日志：`[MCPConnection] coerce: tool=get_issue, param=issue_number: "123" → 123 (string→number)`

#### Scenario: 无转换时不记录

- **GIVEN** tool `get_issue` 的所有参数类型均已匹配
- **WHEN** 系统检查完参数
- **THEN** 不产生任何 coerce 相关日志
