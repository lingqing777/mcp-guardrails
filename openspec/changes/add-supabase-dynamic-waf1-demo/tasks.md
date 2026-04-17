## 1. Supabase 目标接入

- [x] 1.1 新增 `supabase` MCP server 配置方案，明确支持的接入方式（远程 URL / 本地 server command）和所需环境变量
- [x] 1.2 新增 Supabase demo 所需的最小数据模型说明：用户可写表、敏感表、公开表
- [x] 1.3 在项目文档或 demo 说明中补充 Supabase 演示启动与配置步骤

## 2. 动态 WAF1 策略层

- [x] 2.1 在 `mcp-hub/src/waf1/` 新增动态策略模块，支持按 tool profile 执行检查
- [x] 2.2 为高风险 SQL 工具（如 `supabase__execute_sql`）定义 profile：语句类型、敏感 schema/table、危险写回模式、公开表规则
- [x] 2.3 将动态策略层接入 `validateToolCall()`，确保 Dashboard 和 `/mcp` 路径都经过同一套检查
- [x] 2.4 为动态策略拦截补充统一日志、category、severity、OWASP/MITRE 映射

## 3. Lethal Trifecta 调用链检测

- [x] 3.1 在调用链跟踪中增加 Supabase 相关危险序列：读取用户可写内容 → 执行 SQL → 写公开表/导出
- [x] 3.2 为该序列定义可演示的拦截原因和检测标签，保证 Dashboard 中可见

## 4. Dashboard / Demo 支持

- [x] 4.1 为 Supabase demo 补充最小测试入口或说明，便于在 Dashboard 中重放典型攻击和正常请求
- [x] 4.2 在检测记录 / Monitor 中确认动态策略拦截能与现有 WAF1 记录一起显示

## 5. 验证

- [x] 5.1 验证正常 SQL 请求放行（如读取允许表）
- [x] 5.2 验证直接读取敏感表被动态策略拦截
- [x] 5.3 验证“写公开表回传敏感数据”模式被拦截
- [x] 5.4 验证 `/mcp` 协议路径也能命中同样的动态策略
