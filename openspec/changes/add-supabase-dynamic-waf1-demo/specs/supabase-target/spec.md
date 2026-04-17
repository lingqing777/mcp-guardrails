## ADDED Requirements

### Requirement: Supabase MCP 演示目标接入

层级：MCP Hub / Config / Demo

系统 MUST 支持将 Supabase MCP 作为演示目标接入，供作品赛展示第二类 MCP 风险案例。

#### Scenario: Supabase Server 出现在 MCP 配置中

- **WHEN** 用户完成 Supabase MCP 所需配置
- **THEN** MCP Hub 中 SHALL 能看到 `supabase` server

#### Scenario: Supabase 工具可用于演示

- **WHEN** Supabase server 连接成功
- **THEN** 演示流程 SHALL 能调用高风险 SQL 工具（如 `execute_sql`）和读取用户可写数据的相关工具

### Requirement: Supabase Lethal Trifecta 演示路径

层级：Demo / WAF1

系统 MUST 支持演示以下攻击路径：
- 用户可写内容中包含 Prompt Injection
- Agent 读取该内容后被劫持
- Agent 使用合法 SQL 访问敏感表
- Agent 试图将结果写回公开位置

#### Scenario: 正常数据访问场景

- **WHEN** 用户执行允许范围内的普通查询
- **THEN** 系统 SHALL 放行并返回正常结果

#### Scenario: 高危数据外泄场景

- **WHEN** 用户重放 Lethal Trifecta 类型攻击链
- **THEN** 系统 SHALL 在协议层拦截高风险 SQL 或危险调用链
- **AND** Dashboard 中 SHALL 可见对应检测记录
