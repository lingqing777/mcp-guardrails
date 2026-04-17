## Why

当前作品赛演示主线已经围绕 WordPress / WooCommerce MCP 打通，适合展示 WAF1 对传统恶意 payload（路径穿越、SSRF、Prompt Injection 等）的静态检测能力。

但之前明确想做的第二条展示线，是 Supabase MCP 的 “Lethal Trifecta” 类攻击：

- 攻击者把 Prompt Injection 埋入用户可写数据（ticket/comment/notes）
- AI Agent 读取这些正常业务数据后被劫持
- Agent 使用完全合法的 `execute_sql` 能力读取敏感表、再把结果写回公开表

这类攻击的核心问题不是“明显恶意字符串”，而是“合法工具 + 合法 SQL + 恶意调用链”。现有 WAF1 以正则和检测器为主，对这类攻击的命中率不够高，无法证明系统对高权限 MCP tool 的治理能力。

因此，需要新增第二个 demo 主线，并为其引入一层更动态的 WAF1 策略能力。

## What Changes

- 新增 `supabase-target` 演示能力：接入 Supabase MCP 作为第二个展示案例，提供可重复演示的高风险 SQL 工具场景
- 新增 `dynamic-waf1` 能力：在 WAF1 中加入面向高风险工具的动态策略检查，而不只依赖静态 payload 规则
- 对 `execute_sql` 一类工具增加策略约束：
  - 识别高风险表（auth、vault、secrets、service_role、users 等）
  - 识别高风险语义（批量读取、information_schema、pg_catalog、写公开表）
  - 识别危险调用链（先读用户可写内容，再执行 SQL，再写公开结果）
- 在 Dashboard 中展示 Supabase demo 所需的最小配置与拦截结果

## Capabilities

### New Capabilities

- `supabase-target`: Supabase MCP 演示目标与案例化配置
- `dynamic-waf1`: 面向高风险 MCP 工具的动态策略检测

### Modified Capabilities

- `waf1`: 在现有静态规则 / 检测器之外，补充“工具画像 + 参数语义 + 调用链上下文”的动态策略层
- `dashboard`: 支持 Supabase demo 的可见性和验证入口

## Impact

- **代码**
  - `mcp-hub/src/waf1/` — 新增动态策略模块与 Supabase tool profile
  - `mcp-hub/src/mcp/server.js` / `mcp-hub/src/api/servers.js` — 继续复用统一 WAF1 检测入口
  - `mcp-hub/src/dashboard/app.js` / `services/api.js` — 补充 Supabase demo 的测试与展示
  - `config/mcp-servers.json` — 新增 `supabase` server 定义（远程或本地）
- **WAF2**
  - 非必须依赖。本 change 主体聚焦协议层和工具层治理
- **Docker / 目标环境**
  - 优先支持“外部 Supabase 项目 + MCP Server”的轻量接入
  - 如后续需要，本 change 可再扩展为本地化种子数据环境
- **路由注册顺序**
  - 不新增公开认证边界，仅复用现有 `/api` 和 `/mcp`
- **Dashboard 5 秒刷新**
  - 不应引入额外高频接口，演示数据尽量复用现有统计接口
