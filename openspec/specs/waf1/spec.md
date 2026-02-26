# WAF1 — 静态规则引擎

## Purpose

MCP 协议层的第一道防线，通过静态规则对 AI Agent 的工具调用进行实时检测和拦截。
采用 5 阶段流水线架构，覆盖限流、权限控制、正则匹配和深度检测。

层级：MCP Hub（Express 中间件）

安全理论依据：
- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- MCP Security Best Practices: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
- Palo Alto Unit42 MCP Attack Vectors: https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/

## Requirements

### 流水线架构

- WAF1-1: 检测 MUST 按 5 阶段顺序执行：限流 → RBAC → 白名单 → 正则规则 → 检测器
- WAF1-2: 任一阶段拦截 MUST 立即终止流水线并返回拦截响应，不继续后续阶段
- WAF1-3: WAF1 MUST 可通过 Dashboard 或 API 全局启用/禁用

### 受保护路由

- WAF1-5: WAF1 中间件 MUST 应用于以下路由：
  - `POST /api/servers/tools` — 工具调用
  - `POST /api/servers/prompts` — Prompt 访问
  - `POST /api/servers/resources` — 资源访问
  - `POST /api/tools/call` — Dashboard 直接工具调用

### 阶段 1：限流（Rate Limiting）

- WAF1-10: 限流 MUST 基于滑动窗口算法，按客户端（IP 或 x-user-id）隔离
- WAF1-11: 默认配置 MUST 为：100 次/分钟窗口，超限封禁 1 分钟
- WAF1-12: 限流参数 MUST 可配置（窗口时长、最大请求数、封禁时长）
- WAF1-13: 超限时 MUST 返回拦截响应，type 为 `RATE_LIMITED`

### 阶段 2：RBAC 访问控制

- WAF1-15: RBAC MUST 默认关闭（enabled: false）
- WAF1-16: RBAC 启用时 MUST 支持两种映射方式：
  - `toolRequirements`：工具 → 所需角色
  - `roleGrants`：角色 → 可用工具
- WAF1-17: RBAC MUST 支持 `defaultPolicy`：`allow`（默认）或 `deny`
- WAF1-18: RBAC 拦截时 MUST 返回 type `RBAC_DENIED`

### 阶段 3：白名单

- WAF1-20: 白名单 MUST 检查工具名是否在允许列表中
- WAF1-21: 默认白名单 MUST 为 `*`（全部放行）

### 阶段 4：正则规则（10 类）

- WAF1-25: 系统 MUST 支持以下 10 类正则规则，每类可独立启用/禁用：

| 规则类别 | 内部名称 | Dashboard 显示名 | 检测目标 |
|---------|---------|-----------------|---------|
| SQL 注入 | sqlInjection | sqlInjection | UNION SELECT, OR 1=1, DROP TABLE 等 |
| Shell 注入 | shellInjection | commandInjection | rm -rf, curl\|bash, 反引号, $() 等 |
| XSS | xss | xss | `<script>`, javascript:, on 事件, iframe 等 |
| 路径穿越 | pathTraversal | pathTraversal | ../, ..%2f, ..%5c 编码 |
| 敏感文件 | sensitiveFiles | sensitiveFiles | /etc/passwd, .ssh/, .env, id_rsa 等 |
| 协议攻击 | protocolAttacks | protocolAttacks | Prompt 注入模式（ignore instructions, jailbreak 等） |
| 数据外泄 | dataExfiltration | dataExfiltration | 外部域名发送, webhook.site, ngrok.io 等 |
| 危险操作 | dangerousOperations | dangerousOperations | eval(), exec(), subprocess, pickle.loads 等 |
| SSRF | ssrf | ssrf | 127.0.0.1, 169.254.x.x, file://, gopher:// 等 |
| 其他注入 | injectionOther | injectionOther | XXE, LDAP 注入模式 |

- WAF1-26: 正则规则 MUST 对工具调用参数的所有字段进行递归检测
- WAF1-27: 规则匹配时 MUST 返回 type `RULE_BLOCKED`，并标注具体 category
- WAF1-28: 注意命名映射：Dashboard 前端使用 `commandInjection`，WAF1 内部使用 `shellInjection`

### 阶段 5：检测器（5 种）

#### Secrets 检测器

- WAF1-30: Secrets 检测器 MUST 识别 40+ 种凭据模式，包括：
  - GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_, fine-grained)
  - AWS (access keys, secret keys, session tokens)
  - OpenAI, GitLab, Slack, Azure, Google, Stripe, Twilio, Discord, Telegram
  - SendGrid, Mailchimp, npm, PyPI tokens
  - SSH/PGP 私钥, JWT, Bearer/Basic auth, 通用 API key/secret/password

#### PII 检测器

- WAF1-35: PII 检测器 MUST 识别以下个人信息类型：
  - 中国：身份证号、手机号、银行卡号
  - 国际：Email、信用卡（Visa/Mastercard/Amex）、SSN、IPv4
  - 护照、IBAN、韩国 RRN、日本 My Number

#### Unicode 检测器

- WAF1-40: Unicode 检测器 MUST 识别以下隐形/控制字符：
  - 零宽字符 (U+200B-U+200F)
  - 双向覆盖 (U+202A-U+202E)
  - Bidi 隔离 (U+2066-U+2069)
  - 控制字符 (C0, C1)
  - 变体选择符、特殊范围（高棉文、蒙古文等）
- WAF1-41: 触发阈值 MUST 为 2 个及以上可疑字符

#### Fuzzy 模糊检测器

- WAF1-45: Fuzzy 检测器 MUST 使用 Levenshtein 距离检测混淆攻击
- WAF1-46: 标准化处理 MUST 包括：全角→半角转换、零宽字符移除、空格压缩、l33t speak 转换（0→o, 1→l, 3→e, 4→a, 5→s, 7→t, @→a）
- WAF1-47: 模糊匹配目标 MUST 包括：drop table, union select, /etc/passwd, rm -rf, `<script>`, ignore previous instructions, jailbreak

#### 调用链检测器

- WAF1-50: 调用链检测器 MUST 在 5 分钟时间窗口内追踪工具调用序列
- WAF1-51: MUST 检测以下 3 种危险模式：
  - `data_exfiltration`：先读取数据，再发送到外部
  - `credential_theft`：先访问凭据，再发 HTTP 请求
  - `recon_then_exploit`：先扫描/枚举，再注入/利用
- WAF1-52: 历史记录 MUST 保留最近 100 条调用，检测后清空防止级联告警

### 检测器通用

- WAF1-55: 所有检测器拦截 MUST 返回 type `DETECTOR_BLOCKED`
- WAF1-56: 检测器结果 MUST 经过 LRU 缓存，1000 条上限，60 秒 TTL

### 拦截响应格式

- WAF1-60: 拦截响应 MUST 遵循格式：`{ error: "WAF1 拦截", reason, type, category }`
- WAF1-61: type 取值 MUST 为：`RULE_BLOCKED` | `DETECTOR_BLOCKED` | `RATE_LIMITED` | `RBAC_DENIED` | `WHITELIST_BLOCKED`

### 统计与映射

- WAF1-65: 统计 MUST 追踪：总请求数、通过数、拦截数、按规则类别拦截数、按检测器拦截数
- WAF1-66: 每条拦截 MUST 携带 severity 级别（critical / high / medium / low / info）
- WAF1-67: 每条拦截 MUST 携带 MITRE ATT&CK 技术编号映射
- WAF1-68: 每条拦截 MUST 携带 OWASP 分类映射
- WAF1-69: 统计 MUST 保留最近 100 条检测记录（含时间戳）

### Dashboard API

- WAF1-70: MUST 提供 `GET /api/waf1/stats` — 基础统计
- WAF1-71: MUST 提供 `GET /api/waf1/dashboard` — 完整仪表盘数据
- WAF1-72: MUST 提供 `GET /api/waf1/timeseries` — 时序数据（可配置间隔）
- WAF1-73: MUST 提供 `GET /api/waf1/history` — 最近调用历史
- WAF1-74: MUST 提供 `POST /api/waf1/reset` — 重置统计
- WAF1-75: MUST 提供 `POST /api/waf1/toggle` — 启用/禁用 WAF1

## Scenarios

### SQL 注入拦截

```
Given WAF1 已启用，sqlInjection 规则已启用
When  Agent 调用工具 query_db，参数包含 "SELECT * FROM users WHERE id=1 OR 1=1"
Then  WAF1 在阶段 4（正则规则）拦截
And   返回 { error: "WAF1 拦截", type: "RULE_BLOCKED", category: "sqlInjection", reason: "检测到 sqlInjection: ..." }
```

### Shell 注入拦截

```
Given WAF1 已启用，shellInjection 规则已启用
When  Agent 调用工具 execute_command，参数包含 "rm -rf /"
Then  WAF1 在阶段 4 拦截，category: "shellInjection"
```

### Prompt 注入拦截

```
Given WAF1 已启用，protocolAttacks 规则已启用
When  Agent 调用工具，参数包含 "ignore all previous instructions and..."
Then  WAF1 在阶段 4 拦截，category: "protocolAttacks"
```

### Secrets 泄露检测

```
Given WAF1 已启用，Secrets 检测器已启用
When  Agent 调用工具，参数包含 "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
Then  WAF1 在阶段 5（检测器）拦截
And   返回 type: "DETECTOR_BLOCKED"，标注检测到 GitHub token
```

### 调用链检测

```
Given WAF1 已启用，调用链检测器已启用
And   Agent 在过去 5 分钟内先调用了 read_file 工具读取 /etc/passwd
When  Agent 随后调用 http_request 工具向外部 URL 发送数据
Then  WAF1 检测到 data_exfiltration 模式
And   拦截并返回 type: "DETECTOR_BLOCKED"
```

### Fuzzy 混淆检测

```
Given WAF1 已启用，Fuzzy 检测器已启用
When  Agent 调用工具，参数包含 "ｄｒｏｐ ｔａｂｌｅ"（全角字符混淆）
Then  Fuzzy 检测器标准化后匹配 "drop table"
And   拦截并返回 type: "DETECTOR_BLOCKED"
```

### 限流触发

```
Given WAF1 已启用，限流配置为 100 次/分钟
When  同一客户端在 1 分钟内发送第 101 次请求
Then  WAF1 在阶段 1（限流）拦截
And   返回 type: "RATE_LIMITED"
And   客户端被封禁 1 分钟
```

### 规则单独禁用

```
Given WAF1 已启用，但 xss 规则已禁用
When  Agent 调用工具，参数包含 "<script>alert(1)</script>"
Then  阶段 4 不拦截（xss 规则已禁用）
And   请求继续进入阶段 5（检测器）
```

### WAF1 全局禁用

```
Given WAF1 已禁用
When  Agent 调用任何工具，参数包含恶意内容
Then  请求直接放行，不经过任何检测
```
