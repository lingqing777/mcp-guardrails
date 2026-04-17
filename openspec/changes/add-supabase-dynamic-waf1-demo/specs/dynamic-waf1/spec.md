## ADDED Requirements

### Requirement: 高风险 MCP 工具动态策略检查

层级：WAF1

系统 MUST 对高风险 MCP 工具支持动态策略检查，不得仅依赖静态正则规则。

动态策略检查 MUST 至少支持：
- tool profile 匹配
- SQL 语句类型识别
- 敏感 schema/table 匹配
- 危险写回模式识别
- 风险分级与结构化拦截响应

#### Scenario: 敏感表读取被拦截

- **WHEN** Agent 调用高风险 SQL 工具，请求访问 `auth.users`、`vault.secrets`、`service_role` 或其他受保护表
- **THEN** 系统 MUST 返回拦截结果
- **AND** 响应中 MUST 标注动态策略命中的原因

#### Scenario: 正常查询放行

- **WHEN** Agent 调用高风险 SQL 工具，但 SQL 仅访问允许的业务表且不包含危险写回模式
- **THEN** 系统 MUST 放行请求

#### Scenario: 公开表回传敏感数据被拦截

- **WHEN** Agent 调用高风险 SQL 工具，试图通过 `insert into public.* select ...` 或等价方式把敏感数据写回公开表
- **THEN** 系统 MUST 拦截该请求

### Requirement: 动态策略层复用统一 WAF1 入口

层级：WAF1 / MCP Hub

动态策略层 MUST 接入 `validateToolCall()`，使 `/api/tools/call`、`/api/servers/tools` 和 `/mcp` 共享相同的策略检查逻辑。

#### Scenario: Dashboard 路径命中动态策略

- **WHEN** Dashboard 通过工具测试入口调用高风险 SQL 工具
- **THEN** 动态策略检查 MUST 生效

#### Scenario: MCP 协议路径命中动态策略

- **WHEN** Agent 通过 `/mcp` 调用同一高风险 SQL 工具
- **THEN** 动态策略检查 MUST 生效
- **AND** 与 Dashboard 路径保持一致的风险判定

### Requirement: Lethal Trifecta 调用链检测

层级：WAF1

系统 MUST 支持对“读取用户可写内容 → 执行高风险 SQL → 写公开结果”这类调用链进行检测。

#### Scenario: 典型 Supabase 攻击链被识别

- **WHEN** Agent 先读取用户可写表中的文本内容，随后执行敏感 SQL，再尝试写回公开表
- **THEN** 系统 MUST 将该序列识别为高风险调用链并拦截
