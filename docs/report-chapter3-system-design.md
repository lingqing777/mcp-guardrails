# 第三章 系统设计

## 3.1 系统设计概述

MCP Guardrails 面向 AI Agent 调用 MCP 工具后进一步访问 Web/API 业务系统的典型场景，采用“控制面治理 + 数据面防护”的双层级联网关架构。系统并不将 MCP 请求简单视为普通 HTTP 流量，也不将所有安全判断交给大模型完成，而是在 Agent、MCP Server 与后端 Web/API 服务之间分别建立协议感知的控制面防线和本地优先的数据面防线。

系统总体链路如图 3.1 所示。AI Agent 或 MCP Client 首先连接 MCP Hub，所有 `tools/call` 请求在进入真实 MCP Server 前由 WAF1 执行控制面治理；通过治理的工具调用继续转发至 MCP Server 或工具适配器；当工具进一步访问 WordPress、WooCommerce、Supabase 或其他 Web/API 目标系统时，请求流量进入 WAF2 HTTP 反向代理，由 WAF2 完成归一化解码、本地攻击评分、风险路由与灰区深度分析。Dashboard 作为交互与审计入口，通过 REST API 周期性聚合 WAF1 与 WAF2 的健康状态、检测记录、路由指标和配置状态。

```text
┌────────────────────────────────────────┐
│          AI Agent / MCP Client          │
└──────────────────┬─────────────────────┘
                   │ MCP 请求
                   ▼
┌────────────────────────────────────────┐
│        MCP Hub :4000 / WAF1             │
│  控制面治理：权限、参数、调用链、策略      │
└──────────────────┬─────────────────────┘
                   │ 过滤后的 tools/call
                   ▼
┌────────────────────────────────────────┐
│        MCP Server / 工具适配器           │
└──────────────────┬─────────────────────┘
                   │ HTTP / Web / API 流量
                   ▼
┌────────────────────────────────────────┐
│        WAF2 :8081 / HTTP Proxy          │
│  数据面防护：归一化、评分、RAG、ReAct      │
└──────────────────┬─────────────────────┘
                   │ 过滤后的业务请求
                   ▼
┌────────────────────────────────────────┐
│ WordPress / WooCommerce / Supabase 等系统 │
└────────────────────────────────────────┘

┌────────────────────────────────────────┐
│ Dashboard：态势感知、配置管理、日志审计、评测指标 │
└────────────────────────────────────────┘
```

图 3.1 MCP Guardrails 双层级联架构

从逻辑职责上看，系统可划分为四个平面。

第一，**MCP 控制面治理平面**。该平面由 MCP Hub 与 WAF1 组成，关注 Agent 是否有权调用某个工具、工具参数是否触发规则、调用链是否呈现危险模式，以及针对 Supabase 等高风险工具的动态策略是否被违反。WAF1 的核心优势在于它理解 MCP 工具调用语义，能够看到工具名称、参数结构、调用者身份和近期调用序列。

第二，**Web/API 数据面防护平面**。该平面由 WAF2 HTTP 反向代理组成，关注 MCP 工具实际发出的 HTTP 请求与响应是否包含 SQL 注入、XSS、命令注入、路径穿越、SSRF、Prompt 注入、凭据泄露、数据外泄等风险。WAF2 不依赖单一路径判断，而是采用本地优先管线：先通过确定性规则、归一化解码和本地攻击评分处理大部分请求，再将少量灰区请求送入 RAG 证据检索、local LLM one-shot 或 ReAct 深度分析。

第三，**交互与审计平面**。Dashboard 提供统一的可视化入口，展示 MCP Server 连接状态、工具清单、WAF1/WAF2 拦截记录、攻击类别统计、本地评分、RAG 命中、路由分布、缓存命中率、模型错误数和平均延迟等指标。该平面服务于作品演示、运维配置和攻击回溯。

第四，**存储与评测支撑平面**。系统保存规则配置、运行统计、近期检测记录、RAG 向量知识库、LLM 缓存和评测响应头。WAF2 在评估模式下通过 `X-Waf2-*` 响应头输出判定类别、本地评分、RAG 分数、路由路径、规范化摘要和延迟信息，支撑后续实验章节中的可复现实验与失败分析。

系统设计遵循以下原则。

1. **协议感知**：WAF1 不只检查原始文本，而是以 MCP 工具调用为治理对象，解析工具名、参数、调用者与调用上下文。
2. **双层互补**：WAF1 处理 Agent 工具调用意图，WAF2 处理工具执行后产生的 HTTP/Web/API 载荷，避免单层防护出现视野盲区。
3. **本地优先**：请求体、Cookie、Token、MCP 参数、RAG 查询、模型提示和审计日志默认留在本地，在线模型仅作为显式配置的对照或备用路径。
4. **低成本实时拦截**：确定性规则、本地评分和风险路由优先执行，只有灰区请求进入模型相关路径，减少延迟和推理成本。
5. **可观测与可复现**：Dashboard、检测记录、评测响应头和失败分析脚本共同形成“运行拦截 + 实验验证 + 失败归因”的工程闭环。

为保证报告描述与工程实现一致，表 3.1 给出了系统关键模块与代码落点的对应关系。

| 系统模块 | 主要代码位置 | 实现职责 |
| --- | --- | --- |
| MCP Hub / MCP 端点 | `mcp-hub/src/mcp/server.js` | 聚合下游 MCP Server，提供 `/mcp` 与 `/messages`，支持 SSE 与 Streamable HTTP |
| WAF1 检测入口 | `mcp-hub/src/waf1/index.js` | 对 MCP `tools/call` 执行速率限制、RBAC、白名单、规则、调用链、动态策略和专项检测 |
| WAF1 调用链 | `mcp-hub/src/waf1/call-chain.js` | 维护同一客户端近期工具调用历史，检测数据外泄、凭证窃取、侦察后利用和 Supabase Lethal Trifecta |
| Supabase SQL 策略 | `mcp-hub/src/waf1/supabase-sql.js`、`mcp-hub/src/waf1/dynamic-policy.js` | 解析 SQL 语句类型、敏感对象、公开写回和导出行为 |
| WAF2 代理主程序 | `waf2/waf2_proxy.py` | 提供 HTTP 反向代理、请求/响应检测、RAG/LLM/ReAct 调度、统计与管理 API |
| WAF2 归一化 | `waf2/normalization.py` | URL/Unicode/HTML/Base64/JSON/路径等多层规范化处理 |
| WAF2 本地评分 | `waf2/local_attack_score.py` | 对多类 Web 与 Agent 攻击进行确定性本地评分 |
| WAF2 风险路由 | `waf2/risk_router.py` | 在 direct block、fast pass、one-shot、ReAct 与 fallback 之间选择路径 |
| RAG 知识库 | `waf2/rag/`、`waf2/rag/data/manifest.json` | 本地向量知识库、ONNX embedding 模型与 ChromaDB 索引 |
| Dashboard | `mcp-hub/src/dashboard/` | 前端态势感知、配置管理、日志审计和检测记录展示 |
| 评测辅助 | `waf2/eval_headers.py`、`waf2/rag/scripts/` | 输出 `X-Waf2-*` 评测头，生成 JSONL 与失败分析报告 |

表 3.1 关键模块与代码实现对应关系

## 3.2 WAF1 控制面治理层

WAF1 部署在 MCP Hub 层，是 Agent 请求触达真实 MCP Server 前的第一道防线。与传统 HTTP WAF 不同，WAF1 的输入不是普通网页请求，而是结构化 MCP 工具调用。它能够从请求中提取工具名称、参数对象、客户端标识和用户标识，并结合内存中的近期调用历史进行多阶段判断。

WAF1 的目标不是替代 MCP Server 的业务逻辑，而是在 MCP 协议入口处补齐默认缺失的安全治理能力：最小权限、工具暴露面控制、参数规则检测、敏感信息识别、调用链追踪和动态策略拦截。

从代码实现看，WAF1 不是独立旁路扫描器，而是直接嵌入 MCP Hub 的请求处理路径中。`mcp-hub/src/mcp/server.js` 在为每类能力注册 request handler 时，对 `tools` 类型的调用执行 `validateToolCall(originalName, arguments, context)`。若 WAF1 返回拦截结果，MCP Hub 会抛出 `McpError`，工具调用不会继续转发至真实 MCP Server。当前实现重点保护 `tools/call`，因为它是 Agent 执行动作和触发高危能力的主要入口；`resources` 与 `prompts` 的列表和读取能力仍由 MCP Hub 正常聚合，可作为后续扩展的防护范围。

MCP Hub 同时支持 SSE 与 Streamable HTTP 两种 HTTP 传输形态：SSE 客户端通过 `GET /mcp` 建立连接，并通过 `POST /messages?sessionId=...` 发送消息；Streamable HTTP 客户端通过 `POST /mcp` 与 `Mcp-Session-Id` 头维持会话。WAF1 使用 MCP 会话标识作为 `clientId`，并在默认场景下使用 `mcp-agent` 作为 `userId`，从而将检测结果与具体 Agent 会话关联。

### 3.2.1 多阶段检测流水线

WAF1 采用顺序执行的多阶段检测流水线。任一阶段判定为拦截时，请求立即终止并返回拒绝响应；只有全部阶段通过后，工具调用才会继续转发至后端 MCP Server。该设计使高置信度、低成本的检测逻辑优先执行，减少后续阶段的计算压力。

**Algorithm 1 WAF1 控制面检测流水线**

```text
Input:
  tool_name: MCP 工具名称
  args:      工具参数对象
  context:   { client_id, user_id, source }

Output:
  decision ∈ {Pass, Block}, reason

1. if WAF1 is disabled:
2.     return Pass

3. record_request()

4. if rate_limit_exceeded(context.client_id):
5.     return Block, "请求频率超限"

6. if not rbac_allow(context.user_id, tool_name):
7.     return Block, "用户无该工具调用权限"

8. if not whitelist_allow(tool_name):
9.     return Block, "工具不在白名单中"

10. if regex_rule_match(args, tool_name):
11.     return Block, "命中静态规则"

12. chain_result = call_chain_check(tool_name, args, context.client_id)
13. if chain_result.detected:
14.     return Block, "命中危险调用链"

15. policy_result = dynamic_policy_check(tool_name, args)
16. if not policy_result.allowed:
17.     return Block, "命中动态策略"

18. detector_results = run_detectors(tool_name, args, chain_result)
19. if any detector blocks:
20.     return Block, "命中专项检测器"

21. record_pass()
22. return Pass, "合法请求"
```

流水线包含以下阶段。

**阶段一：速率限制。** 系统以 `client_id` 为粒度维护请求计数器，对高频工具调用进行限流。当某一 Agent 在短时间内持续触发大量请求时，WAF1 返回 429 响应，降低暴力探测、资源滥用和拒绝服务风险。

**阶段二：RBAC 权限校验。** 系统维护用户、角色与工具之间的授权关系。当 RBAC 启用时，WAF1 根据 `user_id` 与 `tool_name` 判断调用是否被允许。该机制将 MCP 默认的“连接后可调用所有工具”收敛为最小权限模型。

**阶段三：工具白名单校验。** 白名单用于控制当前环境允许暴露给 Agent 的工具集合。若管理员仅希望开放 WordPress 查询类工具，则文件写入、系统命令、数据库执行等工具即使存在于 MCP Server 中，也会在 WAF1 入口被拦截。

**阶段四：静态规则检测。** 该阶段对工具参数对象进行序列化与递归检查，匹配十类高风险模式：SQL 注入、Shell/命令注入、敏感文件访问、Prompt Injection/Tool Poisoning、数据外泄、XSS、危险操作、路径遍历、SSRF 以及 XXE/LDAP 等其他注入模式。对于 Supabase `execute_sql` 一类合法承载 SQL 的管理工具，系统避免简单套用通用 SQL 注入规则，而将其下沉至动态 SQL 策略阶段进行语义化判断。

**阶段五：调用链追踪。** 该阶段记录当前 Agent 的近期工具调用，并基于时间窗口匹配多步危险行为，例如数据外泄、凭证窃取、侦察后利用和 Supabase Lethal Trifecta。调用链检测解决的是“单次调用合法、组合后危险”的问题。

**阶段六：动态策略检测。** 该阶段面向特定高危工具执行更细粒度的运行时策略。目前系统重点实现 Supabase SQL 动态策略，对 SQL 类型、敏感对象、公开写回和导出行为进行分析。

**阶段七：专项检测器。** 专项检测器用于补充静态规则无法稳定覆盖的风险，包括 Secrets 检测、PII 检测、Unicode 异常检测和 Fuzzy Attack 检测。它们与正则规则解耦，便于独立扩展和调试。

为降低重复检测成本，WAF1 在专项检测器前引入内存检测缓存。当前实现中缓存容量为 1000 条，TTL 为 60 秒，主要用于 Secrets、PII、Unicode 和 Fuzzy 检测的重复输入复用。WAF1 统计器同时记录总请求、放行、拦截、规则类别、检测器类别、最近检测记录、速率限制状态和缓存大小，并通过 `/api/waf1/stats` 与 `/api/waf1/dashboard` 暴露给 Dashboard。

WAF1 还提供了一组轻量管理接口：`/api/waf1/stats` 返回基础统计，`/api/waf1/dashboard` 返回 Dashboard 聚合数据，`/api/waf1/timeseries` 返回按时间窗口聚合的拦截序列，`/api/waf1/history` 返回最近调用链历史，`/api/waf1/reset` 用于重置统计，`/api/waf1/toggle` 用于启停 WAF1。上述接口均由 `mcp-hub/src/api/waf1-routes.js` 注册。

### 3.2.2 调用链追踪检测

许多 Agent 攻击并不依赖单次明显恶意调用，而是通过多个看似正常的工具调用组合完成。例如，Agent 先读取用户可控内容，再访问敏感资源，最后将结果写入外部可见位置。若只检查单次 `tools/call`，每一步都可能被视为合法业务操作。WAF1 的调用链追踪模块正是为此类组合风险设计。

调用链模块为每次工具调用记录工具名称、参数对象、时间戳和 `client_id`。系统维护固定大小的历史窗口，默认最多保留 100 条近期调用，并仅在 5 分钟时间窗口内匹配同一客户端的调用序列。该实现不追求完整程序级数据流还原，而采用轻量语义匹配：根据工具名、参数文本、SQL 对象和调用顺序判断是否形成高危行为链。

当前实现覆盖四类危险调用链。

**数据外泄链 `data_exfiltration`。** 当 Agent 先调用读取、查询、搜索、获取类工具，随后调用发送、上传、写入、转发类工具时，系统认为其可能正在将读取到的数据外发。该规则用于捕捉“读敏感数据后发送到外部”的通用模式。

**凭证窃取链 `credential_theft`。** 当参数中出现 `password`、`secret`、`key`、`token`、`credential`、`.env`、`.ssh`、`id_rsa` 等凭证相关特征后，又出现 `http`、`curl`、`wget`、`fetch`、`request` 等外部请求特征时，系统判定存在凭证窃取与外传风险。

**侦察后利用链 `recon_then_exploit`。** 当 Agent 先出现 `scan`、`nmap`、`recon`、`enumerate`、`discover` 等侦察行为，随后出现 `exploit`、`inject`、`attack`、`shell`、`reverse` 等利用行为时，系统阻断后续阶段，降低自动化攻击链继续推进的可能。

**Supabase Lethal Trifecta 链 `supabase_lethal_trifecta`。** 当同一 Agent 在时间窗口内依次出现“读取用户可写表”“访问敏感 SQL 对象”“将结果写回公开表或执行导出行为”时，系统判定为 Lethal Trifecta 攻击链。该规则对应 Supabase MCP 中较典型的间接 Prompt 注入外泄场景。

**Algorithm 2 调用链匹配逻辑**

```text
Input:
  current_call = { tool, args, client_id, timestamp }
  history      = 最近调用历史
  chains       = 危险调用链模式集合

Output:
  detected ∈ {true, false}, chain_name

1. append current_call to history
2. trim history to MAX_HISTORY
3. recent_calls = calls in last 5 minutes with same client_id

4. for each chain in chains:
5.     last_step = chain.steps[-1]
6.     if not last_step.match(current_call):
7.         continue

8.     step_index = len(chain.steps) - 2
9.     for call in reverse(recent_calls without current_call):
10.        if chain.steps[step_index].match(call):
11.            step_index = step_index - 1
12.        if step_index < 0:
13.            clear history to avoid repeated alerts
14.            return true, chain.name

15. return false, null
```

该设计的优势在于开销小、解释性强、适合实时网关；局限在于它主要基于规则化行为模式，无法完全还原跨工具的数据流。对于攻击间隔超过时间窗口的慢速攻击，系统可通过增大窗口、增强日志关联或结合 WAF2 响应侧检测进行补充。

### 3.2.3 动态 SQL 策略与工具画像扩展

静态规则适合发现通用攻击载荷，但对于数据库管理类工具，简单规则容易产生误报。例如，`execute_sql` 工具天然会携带 SQL 语句，不能因为参数中出现 `select`、`insert` 或 `update` 就直接判定为攻击。因此，WAF1 引入动态策略引擎，对高危工具执行与工具语义相关的细粒度分析。

当前实现重点覆盖 Supabase SQL 场景。系统识别 `execute_sql` 与 `supabase__execute_sql` 等工具名称，并从 `sql`、`query`、`statement`、`command`、`text`、`input` 或 `statements` 字段中提取 SQL 语句。随后，动态策略模块对 SQL 进行规范化，识别语句类型、敏感对象、用户可写对象、公开写回目标和导出行为。

敏感对象包括 `auth.users`、`auth.sessions`、`auth.identities`、`vault.secrets`、`information_schema`、`pg_catalog`、`service_role`、`storage.objects` 等。用户可写对象包括 `public.tickets`、`public.comments`、`public.notes`、`public.messages` 等。公开写回行为包括向 `public.*` 表执行 `insert`、`update` 或 `create table`。导出行为包括 `COPY TO`、`pg_write_file`、`http_post` 等。

当 SQL 访问敏感对象、将敏感查询结果写回公开表，或存在明显导出行为时，动态策略直接拦截请求，并在检测记录中标注策略名称、语句类型、受保护对象、公开写回目标和风险方向。

**Algorithm 3 Supabase 动态 SQL 策略**

```text
Input:
  tool_name, args

Output:
  allowed ∈ {true, false}, reason

1. if tool_name is not Supabase SQL tool:
2.     return allowed

3. sql = extract_sql(args)
4. if sql is empty:
5.     return allowed

6. analysis = analyze_sql(sql)

7. if analysis.statement_type not in allowed_statement_types:
8.     return blocked, "不允许的 SQL 语句类型"

9. if analysis.dangerous_writeback:
10.    return blocked, "敏感查询结果写回公开表"

11. if analysis.exports_data:
12.    return blocked, "导出型 SQL 或外部写出行为"

13. if analysis.sensitive_objects is not empty:
14.    return blocked, "访问受保护对象"

15. return allowed
```

该策略体现了 WAF1 的工具画像思想：不同工具具有不同风险结构，不能只依靠统一正则规则处理。后续系统可在同一框架下扩展更多工具画像，例如文件系统工具的路径策略、WordPress/WooCommerce 工具的内容发布策略、云服务工具的资源范围策略等。

### 3.2.4 Supabase Lethal Trifecta 检测模块

Supabase Lethal Trifecta 是本文重点关注的调用链攻击之一。其核心风险在于 Agent 同时具备三类能力：读取用户可控输入、访问敏感数据、向外部可见位置写出数据。攻击者可以将恶意指令植入工单、评论或消息表，等待 Agent 在正常处理业务数据时读取该内容，再诱导其查询敏感表并将结果写回公开区域。

WAF1 针对该场景实现了专用检测逻辑。系统首先识别用户可写表读取行为，例如查询 `tickets`、`comments`、`notes`、`messages` 等对象；随后识别敏感 SQL 访问行为，例如访问 `auth.users`、`vault.secrets`、`pg_catalog`、`information_schema` 等对象；最后识别公开写回或导出行为，例如向 `public.*` 表写入，或使用 `COPY TO`、`pg_write_file`、`http_post` 等方式外传数据。

**Algorithm 4 Supabase Lethal Trifecta 检测**

```text
Input:
  call_chain: 同一 client_id 在时间窗口内的调用序列

Output:
  is_attack ∈ {true, false}

1. step1_found = false
2. step2_found = false

3. for call in call_chain ordered by timestamp:
4.     if not step1_found and is_user_writable_read(call):
5.         step1_found = true
6.         continue

7.     if step1_found and not step2_found and is_sensitive_sql_access(call):
8.         step2_found = true
9.         continue

10.    if step1_found and step2_found and is_public_write_or_export(call):
11.        return true

12. return false
```

当三步按序出现时，WAF1 在第三步阻断请求。该策略避免在正常读取工单或正常查询数据库时过早拦截，而是在攻击链即将形成外泄闭环时进行阻断，兼顾业务可用性与安全性。

## 3.3 WAF2 数据面本地优先防护层

WAF2 是系统的数据面防护层，以 FastAPI 构建为 HTTP 反向代理，部署在 MCP Server 或工具适配器访问后端 Web/API 服务的路径上。其职责是检测工具实际产生的 HTTP 请求与响应，覆盖传统 Web 攻击、Agent 语义攻击和数据外泄风险。

WAF2 的核心定位是本地优先智能 WAF，而不是“所有请求都交给 RAG 或 ReAct”。系统首先通过确定性本地层处理大多数请求：归一化解码、静态规则、本地攻击评分和风险路由。只有无法高置信度判定的灰区请求，才进入 RAG 证据检索、local LLM one-shot 或 ReAct 深度分析路径。该设计降低了延迟、模型成本和敏感数据外传风险。

### 3.3.1 本地优先检测管线

WAF2 请求侧处理流程如图 3.2 所示。

```text
HTTP Request
    │
    ▼
Normalize / Decode
  - URL / double URL decode
  - Unicode escape decode
  - HTML entity decode
  - JSON and nested JSON extraction
  - suspicious Base64 decode
  - path normalization
    │
    ▼
Local Attack Score
  - SQLi / XSS / Command Injection
  - Path Traversal / SSRF
  - Prompt Injection / Data Exfiltration
  - Credential Leakage / MCP Tool Abuse
  - Auth Bypass / Insecure Deserialization
    │
    ▼
Pre Route
  ├─ high confidence → Direct Block
  ├─ low risk        → Fast Pass
  └─ gray zone       → Static/RAG/Router
                         │
                         ▼
                  RAG Knowledge Evidence
                         │
                         ▼
                    Risk Router
             ┌───────────┼───────────┐
             ▼           ▼           ▼
        Fast Pass   Local LLM    ReAct Deep
                    One-shot     Inspection
                                      │
                                      ▼
                         RAG-decisive fallback rescue
```

图 3.2 WAF2 本地优先检测管线

**阶段一：归一化与解码。** 攻击者常通过编码、嵌套和混淆绕过简单规则。WAF2 在所有后续判断前先构造请求的规范化视图，处理 URL 解码与双重 URL 解码、Unicode 转义、HTML 实体、嵌套 JSON/Python 字面量、可疑 Base64 片段、路径归一化、SQL 注释压缩和零宽字符等情况。归一化模块同时输出摘要信息，如是否发生变化、百分号编码数量、Unicode 转义数量、HTML 实体数量、Base64 解码数量和 JSON 片段数量，供风险路由使用。

**阶段二：本地攻击评分。** 归一化后，系统使用确定性规则对请求进行多类别评分。评分类别覆盖 SQL 注入、XSS、命令注入、路径穿越、SSRF、Prompt 注入、数据外泄、凭据泄露、MCP 工具滥用、认证绕过、不安全反序列化和历史探针请求等。评分器不是最终的唯一判定器，而是为路由器提供快速、可解释的本地风险信号。

**阶段三：预路由。** 若本地评分超过直接拦截阈值，系统立即返回拦截；若请求处于低风险业务上下文或低于快速放行阈值，系统直接放行；其余请求进入灰区路径。当前默认阈值包括直接拦截阈值、灰区阈值和快速放行阈值，均可通过配置调整。

**阶段四：静态关键词与解码规则补充。** 对未被预路由处理的请求，WAF2 继续执行静态关键词与 decoded static rule 检测，用于捕获高特异性的已知攻击特征。该阶段可以在无需模型的情况下拦截明显载荷。

**阶段五：RAG 本地证据检索。** 灰区请求被转化为检索输入，在本地向量知识库中召回相似攻击样本、良性 hard negative 样本和规则证据。RAG 不直接替代检测器，而是回答“该请求是否像已知攻击或已知良性边界样本”“相似证据属于哪个类别”“证据分数是否足够高”等问题。

**阶段六：风险路由。** 风险路由器综合本地评分、归一化信号、RAG 分数、请求方法和业务上下文，选择后续路径：`static_block`、`fast_pass`、`local_llm_one_shot`、`react_deep_inspection` 或 `fallback`。编码复杂、RAG 高分、Prompt 注入/数据外泄类灰区请求更容易进入 ReAct；普通灰区请求则进入 one-shot 模型判定。

**阶段七：灰区深度分析与失败恢复。** local LLM one-shot 用于一次性语义判断；ReAct deep inspection 用于复杂编码、混淆载荷、RAG 证据冲突、MCP 工具链上下文攻击和潜在数据外泄。若 ReAct 未能输出稳定结论，系统可基于 RAG 证据与本地评分类别执行 conservative fallback rescue，将部分原本会因解析失败而放行的高风险请求转为阻断。

**Algorithm 5 WAF2 请求检测流程**

```text
Input:
  method, path, body, headers

Output:
  decision ∈ {Pass, Block}, route, reason

1. normalization = normalize_request(method, path, body)
2. score = local_attack_score(normalization, headers)

3. pre_route = decide_route(method, path, normalization, score, rag_used=false)
4. if pre_route == static_block:
5.     return Block, "本地评分直接拦截"
6. if pre_route == fast_pass:
7.     return Pass, "低风险快速放行"

8. if static_keyword_match(normalization):
9.     return Block, "命中静态关键词"

10. if decoded_static_rule_match(path, body):
11.     return Block, "解码后命中静态规则"

12. rag_evidence = rag_search(build_rag_input(method, path, body))
13. if rag_evidence is benign hard negative and business context is low risk:
14.     return Pass, "良性边界样本证据支持放行"

15. route = decide_route(method, path, normalization, score, rag_evidence)

16. if route == static_block:
17.     return Block, "RAG 辅助后本地评分拦截"
18. if route == fast_pass:
19.     return Pass, "风险路由快速放行"
20. if route == local_llm_one_shot:
21.     return one_shot_llm_verdict(normalization, rag_evidence)
22. if route == react_deep_inspection:
23.     result = react_agent_verdict(normalization, rag_evidence)
24.     if result is valid:
25.         return result
26.     rescue = rag_decisive_fallback(rag_evidence, score)
27.     if rescue blocks:
28.         return Block, "ReAct 失败后由 RAG/本地评分救援拦截"

29. return fallback_decision()
```

### 3.3.2 RAG 知识库构建

WAF2 的 RAG 知识库是本地安全知识证据层。它不作为默认主检测器，而是在灰区请求中提供相似案例、类别依据和良性边界样本，增强 one-shot 与 ReAct 的判断依据。

当前知识库包含 3364 条向量化条目，来源包括 PayloadsAllTheThings、OWASP CRS、AI-Agent-Attacks 与 WAF2-Benign-Hard-Negatives。覆盖类别包括 SQL 注入、XSS、命令注入、路径穿越、Prompt 注入、数据外泄、SSRF、XXE、认证绕过、敏感数据暴露和不安全反序列化等。系统使用 `sentence-transformers/all-MiniLM-L6-v2` 生成 384 维向量，并存储于本地 ChromaDB 集合中。

知识库构建流程包括数据收集、去重、脱敏、类别标注、向量化和本地索引持久化。为降低误报，系统不仅收录攻击载荷，也收录 benign hard negatives，即表面上包含安全术语但语义上属于安全教育、测试说明或正常业务上下文的样本。风险路由器在看到此类证据时，可以在低风险业务场景下选择快速放行。

RAG 检索输出包括 top-k 证据片段、相似度分数、证据类别、证据来源和 evidence id。Dashboard 与评测响应头会暴露 RAG 是否启用、是否被门控、top score、top category、空结果次数和平均检索延迟等指标，便于分析知识库覆盖度与实际收益。

### 3.3.3 LLM Provider 兼容、缓存与隐私边界

WAF2 的模型调用层通过适配器兼容 OpenAI-compatible、Anthropic 和 Gemini 等接口格式，同时支持本地 Ollama、vLLM、LocalAI、llama.cpp 或自定义本地端点。系统通过 `provider_locality` 与 `privacy_mode` 标识当前模型调用模式：当模型端点位于 localhost、Ollama、vLLM、LocalAI 等本地环境时，系统视为 local provider；否则视为 online provider。在线模型保留为显式配置的基线或备用模式，不是默认的本地优先路径。

为减少重复推理，WAF2 使用基于请求内容、模型配置、RAG 开关、路由配置和请求头摘要的缓存键缓存分析结果。缓存默认最多保存 500 条记录，TTL 为 300 秒。相同工具调用或相同攻击样本在短时间内重复出现时，可直接命中缓存，降低模型调用次数。

WAF2 还实现了失败策略控制。模型超时、解析失败或 ReAct 未产出最终结论时，系统根据 `fail_policy` 选择 fail-open 或 fail-closed；在评估模式下可启用更严格策略，以便测量保守拦截效果。对于 ReAct 失败但 RAG 证据与本地评分共同指向高风险类别的样本，fallback rescue 机制可将其转为阻断，减少模型输出不稳定带来的漏报。

本地优先隐私边界包括 HTTP 请求体、Cookie、Token、API Key、MCP 工具参数、RAG 查询、LLM Prompt 和检测日志。只要系统运行在 local provider 模式，上述内容默认不离开本机。在线 Provider 仅在管理员显式配置时启用，并在 Dashboard 中展示其 locality 与 privacy mode。

### 3.3.4 响应侧检测

除请求侧攻击检测外，WAF2 也对上游业务系统返回的响应执行安全分析。响应侧检测主要关注敏感信息泄露，包括私钥、Token、API Key、数据库凭据、JWT、云服务密钥、PII 和其他高敏字段。

响应检测首先执行静态敏感模式扫描，若命中高置信度泄露特征则直接拦截响应。若配置 `RAG_SCOPE=all`，系统可对响应内容执行 RAG 检索，并调用 ReAct 响应分析器判断是否属于数据泄露。响应侧 ReAct 使用的工具与请求侧类似，但提示目标从“攻击载荷识别”调整为“敏感数据泄露判断”。当响应分析失败时，系统同样可通过 RAG-decisive fallback rescue 对部分高风险响应进行保守拦截。

响应侧检测补足了请求侧无法完全覆盖的场景。例如，某些请求本身并不明显恶意，但上游响应意外包含 Token、私钥或用户隐私数据，此时 WAF2 可在数据离开系统边界前进行阻断。

### 3.3.5 管理 API 与代理入口

WAF2 在 FastAPI 中将管理 API 注册在代理路由之前，所有 `/waf2/*` 路径由管理接口处理，其余路径由 catch-all 代理入口转发到上游目标。该设计使 WAF2 既是数据面代理，也是可观测、可配置的运行时组件。

主要管理接口如下。

| 接口 | 方法 | 功能 |
| --- | --- | --- |
| `/waf2/health` | GET | 返回 WAF2 健康状态、上游地址、模型、本地优先状态、RAG 加载状态和可用 ReAct 工具 |
| `/waf2/config` | GET/POST | 获取或更新上游地址、模型 Provider、RAG、ReAct、本地评分阈值、缓存和 fail policy 等配置 |
| `/waf2/stats` | GET | 返回总请求、拦截、LLM 调用、缓存命中、本地评分、RAG、路由和 ReAct 统计 |
| `/waf2/dashboard` | GET | 返回 Dashboard 聚合展示所需的完整数据结构 |
| `/waf2/detections` | GET | 返回最近检测记录 |
| `/waf2/rag/info` | GET | 返回 RAG 知识库版本、条目数、类别分布、来源分布和 embedding 模型信息 |
| `/waf2/test-llm` | POST | 测试 OpenAI-compatible、Anthropic 或 Gemini 格式模型端点连通性 |
| `/waf2/cache/clear` | POST | 清空 LLM 判定缓存 |
| `/waf2/reset` | POST | 重置运行统计 |
| `/{path:path}` | GET/POST/PUT/DELETE/PATCH/OPTIONS | 主代理入口，执行请求检测、上游转发和响应检测 |

代理入口的实际处理顺序为：读取请求体并记录总请求数；若 WAF2 关闭则直接转发；否则先执行原始静态规则预筛查，再进入 `analyze_request` 本地优先管线；若请求被拦截则返回 403 JSON；若处于评估模式则返回本地 mock 200 并携带评测响应头；否则使用异步 HTTP 客户端转发至上游；收到上游响应后执行 `analyze_response`；若响应含敏感信息则阻断，否则将上游响应返回给调用方。

## 3.4 用户交互层 Dashboard

Dashboard 是 MCP Guardrails 的可视化交互入口，面向演示、运维和审计三类场景。系统采用轻量前端实现，使用原生 JavaScript、模块化组件、Chart.js 和 CSS 构建，不依赖复杂前端框架，便于在作品赛演示环境中快速部署。

Dashboard 并不直接参与核心检测逻辑，而是通过 REST API 周期性拉取 WAF1 与 WAF2 的统计、检测记录和健康状态，并在前端聚合展示。默认刷新间隔可配置，前端同时支持手动刷新、服务状态轮询和配置项更新。

### 3.4.1 功能模块

Dashboard 围绕安全运维工作流组织为五类功能模块。

| 模块 | 核心功能 | 展示重点 |
| --- | --- | --- |
| 态势感知 | 总请求数、拦截数、放行数、攻击类别、严重级别、趋势图 | 展示 WAF1/WAF2 的整体防护效果 |
| MCP Server 管理 | Server 状态、工具清单、连接测试、服务启停状态 | 展示 MCP 接入与工具暴露面 |
| WAF 规则配置 | WAF1 规则开关、WAF2 特性开关、上游地址、模型配置、阈值配置 | 展示策略可调与本地优先模式 |
| 检测记录 | 最近拦截事件、命中规则、攻击类别、路由原因、证据信息 | 支持攻击回溯与答辩演示 |
| 登录认证 | 用户登录、Session Cookie、角色字段 | 限制 Dashboard 与 API 访问 |

表 3.2 Dashboard 功能模块

态势感知模块聚合 WAF1 与 WAF2 指标，展示总请求量、拦截数、拦截率、类别分布和严重级别分布。WAF1 面板突出控制面治理效果，例如规则命中、RBAC 拦截、调用链拦截、动态策略拦截和专项检测器结果。WAF2 面板突出本地优先管线效果，例如本地模式、隐私模式、本地评分直接拦截数、灰区数量、RAG 查询次数、RAG 门控次数、空结果次数、ReAct 进入率、fallback rescue 次数、缓存命中率、LLM 调用次数、LLM 错误数和平均延迟。

MCP Server 管理模块用于展示已接入 Server 的连接状态和工具清单。演示人员可以通过该模块确认 WordPress、WooCommerce、Supabase 等目标是否在线，并观察工具调用经过 WAF1 后的结果。

WAF 规则配置模块允许管理员调整 WAF1 规则开关、WAF2 上游目标、模型 Provider、RAG/ReAct 开关、本地评分阈值和缓存配置。该模块强调系统不是固定脚本，而是可运维、可调参的安全网关。

检测记录模块展示近期 WAF1/WAF2 检测事件。对于 WAF2 事件，记录中会包含 route、route reason、本地评分 top category、RAG top score、provider locality、privacy mode、normalization 摘要等信息。评委可以从单条检测记录看到一次请求为何被阻断或放行。

登录认证模块通过 Session Cookie 保护 Dashboard 和相关 API。用户信息可从配置文件加载，密码使用哈希存储；若配置文件缺失，系统提供环境变量控制的默认管理员兜底账号。当前实现主要满足演示和本地部署需要，生产环境可进一步接入 Redis Session、统一身份认证和更细粒度角色权限。

### 3.4.2 部署架构

系统采用混合部署模式。MCP Hub 与 Dashboard 运行在宿主机或 Node.js 容器中，默认监听 `:4000`；WAF2 以独立 FastAPI 服务运行，默认监听 `:8081`；后端目标系统可以是本地 WordPress/WooCommerce、Supabase 或其他 Web/API 服务。WAF2 的上游地址通过环境变量或 Dashboard 配置指定。

部署流程如下。

1. 启动 MCP Hub，使 Agent 通过 `/mcp`、SSE 或 Streamable HTTP 连接统一入口。
2. 在 MCP Hub 配置中注册需要聚合的 MCP Server，例如 filesystem、WordPress、WooCommerce 或 Supabase。
3. 启动 WAF2，并将上游目标配置为待保护的 Web/API 服务。
4. 将 MCP 工具产生的 HTTP 请求导向 WAF2 代理端口，而不是直接访问目标服务。
5. 登录 Dashboard，检查 WAF1/WAF2 健康状态、规则配置、RAG 知识库状态和检测记录。

该部署方式适合作品赛演示：控制面、数据面、Dashboard 和目标系统可以在同一台开发笔记本或虚拟机上运行，也可以将 Dashboard 暴露为公网 Demo 地址供远程评审访问。由于 WAF2 镜像内置 RAG 运行时依赖和知识库资产，演示环境能够做到较低配置成本的一键启动。

### 3.4.3 演示目标系统与 MCP Abilities

为支撑“Agent-MCP-Web”完整链路演示，项目内置 WordPress/WooCommerce 目标系统配置。`targets/wordpress.yml` 启动 WordPress、MySQL 与相关初始化脚本；`targets/wordpress/setup.sh` 负责安装 WordPress MCP Adapter、WooCommerce、WooCommerce sample products 和 WooCommerce MCP ability 插件，使 Agent 能通过 MCP 调用真实 CMS 与电商系统能力。

项目还在 `targets/wordpress/mu-plugins/mcp-demo-abilities.php` 中注册了用于安全演示的 WordPress abilities。这些能力并非孤立测试函数，而是通过 WordPress Abilities API 暴露给 MCP Adapter，再由 MCP Hub 聚合为 Agent 可调用的 MCP 工具。典型能力包括：

| Ability | 攻击面 | 用途 |
| --- | --- | --- |
| `demo/list-users` | Sensitive Data Exposure | 返回用户 id、用户名、邮箱和角色，用于演示敏感数据访问与外泄风险 |
| `demo/upload-media` | SSRF | 从用户提供的 URL 下载媒体并上传，用于演示 URL 参数触发的 SSRF 风险 |
| `demo/read-file` | Path Traversal / Sensitive Files | 读取 WordPress 目录内文件，用于演示路径穿越、敏感文件访问和 WAF1 参数拦截 |
| `demo/get-settings` | Secrets / Configuration Exposure | 返回站点配置，用于演示配置泄露和响应侧敏感信息检测 |

表 3.3 WordPress 演示能力与安全风险

该演示环境体现了本文双层设计的必要性：当 Agent 调用 `demo/read-file`、`demo/upload-media` 或 WooCommerce 商品/订单工具时，WAF1 可以先根据工具名、参数和调用链判断是否应允许工具执行；若工具执行后继续访问 WordPress/WooCommerce 的 HTTP 接口，WAF2 则负责检测实际 HTTP 请求中的 XSS、SSRF、路径穿越、Prompt 注入或数据外泄载荷。也就是说，同一个演示样本可以同时呈现 MCP 控制面治理和 Web 数据面防护效果。

## 3.5 审计、评测与失败分析闭环

MCP Guardrails 不只提供运行时拦截，还为后续实验评估和结果复现提供专门支撑。作品赛项目需要证明系统“能运行、能拦截、能解释、能复现”，因此本文在系统设计中将审计与评测能力作为独立闭环。

### 3.5.1 运行时审计

WAF1 和 WAF2 均会记录近期检测事件。WAF1 记录工具名、检测阶段、命中类别、拦截原因、严重级别和时间戳；WAF2 记录请求方向、攻击类别、路由路径、本地评分、RAG 证据、模型路径、规范化摘要、provider locality、privacy mode 和延迟信息。Dashboard 从两个服务聚合这些记录，形成统一的攻击态势视图。

从实现上看，WAF1 的 `StatsCollector` 在内存中保留最近 100 条检测记录，并为 Dashboard 生成按类别、严重级别和小时聚合的数据；WAF2 的 `log_detection` 同样在内存中保留最近 100 条检测记录，并追加写入本地 `waf2_log.json`，便于演示后回溯单次攻击的完整判定信息。

为了增强解释性，系统将检测结果映射到 OWASP 与 MITRE ATT&CK 等标签。例如 SQL 注入、命令注入、路径穿越、SSRF、凭据泄露和调用链外泄会对应不同的安全类别与严重等级。该设计使拦截结果不只是“阻断/放行”，还能够回答“为什么阻断”“属于哪类风险”“由哪个阶段发现”。

### 3.5.2 评测响应头

WAF2 提供评估模式。在 `EVAL_MODE=true` 时，系统对命中拦截的请求保持正常拦截逻辑；对于未拦截请求，可不转发真实上游，而是返回本地 200，从而避免评测脚本依赖真实业务系统状态。与此同时，WAF2 会在响应中加入 `X-Waf2-*` 诊断头，输出每个样本的关键判定信号。

典型评测响应头包括：

```text
X-Waf2-Outcome: blocked | passed
X-Waf2-Detected-Category: sql_injection / prompt_injection / ...
X-Waf2-Local-Score-Total: 本地最高风险分
X-Waf2-Local-Score-Top: top 评分类别
X-Waf2-Rag-Used: true | false
X-Waf2-Rag-Top-Score: RAG top score
X-Waf2-Rag-Top-Category: RAG top category
X-Waf2-Route: static_block / fast_pass / local_llm_one_shot / react_deep_inspection / fallback
X-Waf2-Reasons: 路由原因摘要
X-Waf2-Normalize-Meta: frags/b64/pct/uni/changed 等规范化摘要
X-Waf2-Latency-Ms: 请求处理延迟
```

这些响应头使评测脚本无需解析服务日志即可生成结构化 JSONL 结果，便于统计召回率、准确率、F1、误报率、不同路由占比、RAG 命中率、ReAct 进入率和平均延迟。

### 3.5.3 失败分析闭环

系统评测不只输出最终指标，还支持失败样本归因。评测脚本会将漏报与误报样本整理为 JSONL，并进一步生成 failure-analysis 报告。报告将问题归因到不同模块，例如：

1. **Normalization 问题**：编码、嵌套 JSON、Base64 或 Unicode 混淆未被充分还原。
2. **Local Score 问题**：本地评分权重不足、类别识别错误或良性上下文误判。
3. **RAG 覆盖问题**：知识库缺少对应攻击族，或良性 hard negative 不足。
4. **Risk Router 问题**：灰区样本未进入合适的 one-shot/ReAct 路径。
5. **ReAct/Fallback 问题**：模型输出格式不稳定、未产生 final answer，或 rescue 条件过松/过严。
6. **Dashboard 展示问题**：检测记录字段不足，无法解释某次路由或拦截。

通过该闭环，项目可以按照“评测 → 失败分析 → 修正规则/知识库/路由 → 回归测试”的方式迭代，而不是只展示一次性的 Demo 效果。这也是本文系统设计区别于单纯规则脚本或单纯大模型检测器的重要工程特征。

## 3.6 本章小结

本章介绍了 MCP Guardrails 的系统设计。系统以 MCP 控制面和 Web/API 数据面为两条主线：WAF1 部署在 MCP Hub 层，负责工具权限、参数规则、调用链追踪、动态 SQL 策略和专项检测器；WAF2 部署在 HTTP 反向代理层，负责归一化解码、本地攻击评分、RAG 证据检索、风险路由、local LLM one-shot、ReAct 深度分析和响应侧泄露检测。Dashboard 与评测响应头进一步提供可视化、审计和实验复现能力。

整体而言，MCP Guardrails 的设计重点不是将传统 WAF、Prompt Guard 或 RAG/LLM 检测简单叠加，而是将 Agent 工具调用意图、MCP 协议语义、Web/API 攻击载荷和本地优先智能分析统一到一条可部署、可演示、可评测的双层网关链路中。
