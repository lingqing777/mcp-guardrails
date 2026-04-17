## Context

现有 WAF1 的强项是：

- 正则规则：SQL 注入、路径遍历、SSRF、Prompt Injection 等
- 检测器：secrets / pii / unicode / fuzzy / call-chain

这套能力对 WordPress 场景有效，因为 payload 往往本身就含有明显恶意模式。

Supabase MCP 的核心风险不同：

1. 工具能力本身就很危险：`execute_sql`
2. SQL 本身可能是合法语法，不包含典型注入痕迹
3. 真正的恶意在于：
   - 不该访问的表
   - 不该出现的数据流向
   - 不该发生的工具序列

所以，这一条线不能只靠“静态 regex 命中”，需要增加一个策略层。

## Goals / Non-Goals

**Goals**
- 为 Supabase MCP 增加可展示的目标接入方案
- 在 WAF1 中增加动态策略检查，覆盖 `execute_sql` 这类高危工具
- 复用现有 `validateToolCall()` 入口，让 Dashboard 与 `/mcp` 协议路径共享同一套检查
- 让演示可以明确区分：
  - 正常 SQL 放行
  - 高风险 SQL / 高风险调用链拦截

**Non-Goals**
- 不尝试做完整 SQL AST 安全分析器
- 不在第一阶段自建完整 11+ 容器的 Supabase 本地栈
- 不替代 WAF2 的 HTTP 语义分析职责
- 不改变现有 WordPress demo 主线

## Decisions

### 1. 新增“动态策略阶段”，挂在 WAF1 内部

在 `validateToolCall()` 中增加一个新的动态策略检查步骤，放在静态规则之后、统一返回之前执行。

这样可以：
- 继续复用 WAF1 的统计、日志、Dashboard 展示
- 保持 `/api/tools/call`、`/api/servers/tools`、`/mcp` 三条路径一致
- 不引入第二套平行拦截体系

### 2. 策略对象以 tool profile 驱动

第一阶段以高风险 SQL 工具为核心，先定义类似 `supabase__execute_sql` 的 tool profile。

每个 profile 至少包含：
- 风险等级
- 受保护 schema/table 模式
- 允许的 SQL 类型
- 禁止的 SQL 模式
- 公开可写表名单

这样后续 GitHub、filesystem、任意 DB 工具都能复用。

### 3. 第一阶段不做 AST，采用轻量 SQL 语义分类

先实现：
- 语句类型识别：`select` / `insert` / `update` / `delete` / `ddl`
- 敏感对象识别：
  - `auth.users`
  - `vault.secrets`
  - `information_schema.*`
  - `pg_catalog.*`
  - 其他配置化高风险对象
- 危险写回模式识别：
  - `insert into public.* select ...`
  - `create table public.* as select ...`

这是 demo 成本和效果之间最合适的折中。

### 4. 调用链增加 “Lethal Trifecta” 模式

为 call-chain tracker 增加一种更面向 Supabase 的危险序列：
- 读取用户可写内容 / 评论 / 工单
- 紧接着执行高风险 SQL
- 再出现写公开表或导出型 SQL

这正是你们前面想展示的真实攻击模型。

### 5. Supabase demo 先做轻量接入

第一阶段优先支持：
- 外部 Supabase 项目
- 或预置好的远程 / 本地 MCP endpoint

重点放在协议层与工具层防护，而不是首版就把环境复杂度做满。

## Risks / Trade-offs

- **误报正常 SQL**
  - 通过 profile 白名单和只对高风险 tool 开启策略降低影响

- **字符串级 SQL 识别不够精准**
  - 第一阶段接受这个限制，目标先覆盖 demo 的核心攻击路径

- **环境依赖外部项目**
  - 用清晰配置和最小种子数据降低不确定性

- **优先可展示性而非完备性**
  - 当前阶段先证明“静态 WAF1 不够，需要动态策略层”
