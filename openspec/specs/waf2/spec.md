# WAF2 — LLM 语义分析引擎

## Purpose

HTTP 流量层的第二道防线，通过大语言模型对请求意图和响应内容进行语义级分析。
作为反向代理部署于 Docker 容器中，拦截 MCP Server 与目标应用之间的 HTTP 通信。

层级：Docker 容器（独立于 MCP Hub）

安全理论依据：
- OWASP LLM01:2025 Prompt Injection: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- MCP Security Best Practices: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
- Palo Alto Unit42 MCP Attack Vectors: https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/

## Requirements

### 架构

- WAF2-1: WAF2 MUST 以 FastAPI + httpx 反向代理架构运行
- WAF2-2: WAF2 MUST 在 Docker 容器中部署，监听 0.0.0.0:8081
- WAF2-3: WAF2 MUST 可通过 API 或 Dashboard 全局启用/禁用

### 检测流程

- WAF2-5: 检测流程 MUST 为三阶段：请求分析 → 转发 → 响应分析
- WAF2-6: 请求分析和响应分析 MUST 可独立启用/禁用
- WAF2-7: WAF2 禁用时 MUST 直接透传所有请求

### 请求分析

- WAF2-10: 请求分析 MUST 将 HTTP method、path、body 提交给 LLM 判断
- WAF2-11: LLM MUST 返回 `PASS` 或 `BLOCK|<category>|<reason>` 格式
- WAF2-12: 请求分析 MUST 覆盖以下 9 类攻击：

| 类别 | severity | OWASP | MITRE |
|------|----------|-------|-------|
| sql_injection | high | A03:2021 | T1190 |
| xss | medium | A03:2021 | T1189 |
| command_injection | critical | A03:2021 | T1059 |
| path_traversal | high | A01:2021 | T1083 |
| ssrf | high | A10:2021 | T1090 |
| xxe | high | A05:2021 | T1059 |
| prompt_injection | high | LLM01 | T1557 |
| authentication_bypass | critical | A07:2021 | T1078 |
| insecure_deserialization | critical | A08:2021 | T1059 |

### 响应分析

- WAF2-15: 响应分析 MUST 检查目标应用返回内容是否包含敏感数据泄露
- WAF2-16: 响应分析 MUST 覆盖以下 4 类泄露：
  - PII（身份证、手机号、Email、银行卡）
  - 凭据（API Key、密码、Token、私钥）
  - 内部信息（IP 地址、数据库连接串、调试信息）
  - 敏感业务数据

### LLM Provider

- WAF2-20: LLM Provider 通用化 — WAF2 MUST 支持 3 种 API 格式的 LLM Provider：OpenAI 兼容（`openai`）、Anthropic（`anthropic`）、Google Gemini 原生（`gemini`）。`call_llm()` MUST 根据 `format` 配置字段选择对应的请求构造逻辑，不得硬编码任何厂商的 API 地址。

  #### Scenario: format=openai（DashScope）
  - **WHEN** 配置 `format` 为 `openai`，`base_url` 为 `https://dashscope.aliyuncs.com/compatible-mode/v1`
  - **THEN** `call_llm()` 向 `{base_url}/chat/completions` 发送 POST 请求
  - **AND** 使用 `Authorization: Bearer <api_key>` Header
  - **AND** 从响应的 `choices[0].message.content` 取结果

  #### Scenario: format=anthropic（Claude）
  - **WHEN** 配置 `format` 为 `anthropic`，`base_url` 为 `https://api.anthropic.com`
  - **THEN** `call_llm()` 向 `{base_url}/v1/messages` 发送 POST 请求
  - **AND** 使用 `x-api-key: <api_key>` 和 `anthropic-version: 2023-06-01` Header
  - **AND** 请求体使用 `{ model, messages, max_tokens }` 格式
  - **AND** 从响应的 `content[0].text` 取结果

  #### Scenario: format=gemini（Gemini 原生）
  - **WHEN** 配置 `format` 为 `gemini`，`base_url` 为 `https://generativelanguage.googleapis.com`
  - **THEN** `call_llm()` 向 `{base_url}/v1beta/models/{model}:generateContent` 发送 POST 请求
  - **AND** 使用 `x-goog-api-key: <api_key>` Header
  - **AND** 请求体使用 `{ contents: [{role, parts: [{text}]}], generationConfig }` 格式
  - **AND** 从响应的 `candidates[0].content.parts[0].text` 取结果

  #### Scenario: 使用 Ollama 本地 Provider（无 API Key）
  - **WHEN** 配置 `format` 为 `openai`，`base_url` 为 `http://localhost:11434/v1`，`api_key` 为空
  - **THEN** `call_llm()` 向 `{base_url}/chat/completions` 发送 POST 请求
  - **AND** 请求 Header 中不包含 `Authorization` 字段

- WAF2-21: Dashboard LLM 配置字段 — 用户 MUST 可在 Dashboard 配置以下 LLM 字段：Provider（预设下拉）、Base URL、Model、API Key。配置通过 MCP Hub 同步 `base_url`、`model`、`api_key`、`format` 到 WAF2。

  #### Scenario: Dashboard 配置完整 LLM 参数
  - **WHEN** 用户在 Dashboard 选择 Provider 为 Anthropic Claude，填写 API Key
  - **THEN** MCP Hub 同步 `base_url`、`model`、`api_key`、`format: "anthropic"` 到 WAF2 的 `POST /waf2/config`
  - **AND** WAF2 使用 Anthropic 格式进行后续 LLM 调用

- WAF2-22: 支持的 Provider 列表 — WAF2 MUST 兼容以下 LLM Provider（不限于此列表）：

  | Provider | format | Base URL | 默认模型 |
  |----------|--------|----------|----------|
  | 通义千问 (DashScope) | openai | `https://dashscope.aliyuncs.com/compatible-mode/v1` | qwen-turbo |
  | OpenAI | openai | `https://api.openai.com/v1` | gpt-4o-mini |
  | DeepSeek | openai | `https://api.deepseek.com/v1` | deepseek-chat |
  | Anthropic Claude | anthropic | `https://api.anthropic.com` | claude-sonnet-4-5-20250929 |
  | Google Gemini | gemini | `https://generativelanguage.googleapis.com` | gemini-2.5-flash |
  | Moonshot (Kimi) | openai | `https://api.moonshot.cn/v1` | moonshot-v1-8k |
  | 智谱 AI (GLM) | openai | `https://open.bigmodel.cn/api/paas/v4` | glm-4-flash |
  | SiliconFlow | openai | `https://api.siliconflow.cn/v1` | deepseek-ai/DeepSeek-V3 |
  | 百度文心 | openai | `https://qianfan.baidubce.com/v2` | ernie-4.0-8k |
  | 豆包 (火山引擎) | openai | `https://ark.cn-beijing.volces.com/api/v3` | doubao-1.5-pro-32k |
  | Ollama (本地) | openai | `http://localhost:11434/v1` | llama3 |

  #### Scenario: 自定义 Provider
  - **WHEN** 用户选择"自定义"并手动填写 Base URL 和选择 format
  - **THEN** WAF2 使用该自定义配置进行 LLM 调用

- WAF2-23: LLM API 调用失败时 MUST 放行请求，但 MUST 返回 `"ERROR"` 状态（而非 `"PASS"`），并将错误计入 `stats['llm_errors']` 计数器。proxy 层 MUST 区分 `"PASS"`、`"BLOCK"` 和 `"ERROR"` 三种状态。

  #### Scenario: LLM 调用失败 — 放行但标记 ERROR
  - **WHEN** WAF2 已启用，`call_llm()` 因 API Key 无效或网络错误抛出异常
  - **THEN** `call_llm()` MUST 返回字符串 `"ERROR"`
  - **AND** `stats['llm_errors']` MUST 递增 1
  - **AND** proxy MUST 放行请求到上游
  - **AND** 日志 MUST 打印 `[WAF2] ⚠️ LLM 调用失败: {error}`

  #### Scenario: LLM 调用成功 — 正常流程不变
  - **WHEN** `call_llm()` 正常返回 `"PASS"` 或 `"BLOCK|..."`
  - **THEN** proxy 按原有逻辑处理（放行或拦截）
  - **AND** `stats['llm_errors']` 不变

### 缓存

- WAF2-25: LLM 结果 MUST 经过缓存，避免重复调用
- WAF2-26: 缓存 MUST 基于 MD5 哈希，最大 500 条，5 分钟 TTL
- WAF2-27: 缓存命中率 MUST 可通过 API 查询
- WAF2-28: 缓存 MUST 可通过 API 手动清除

### 拦截响应格式

- WAF2-30: 拦截 MUST 返回 HTTP 403
- WAF2-31: 拦截响应格式 MUST 为：`{ error: "WAF2 拦截", direction: "request"|"response", category, severity, reason, owasp, mitre }`

### 统计

- WAF2-35: 统计 MUST 追踪：总请求数、通过数、拦截数（区分请求拦截/响应拦截）
- WAF2-36: 统计 MUST 包含按 category 和 severity 的分类统计
- WAF2-37: 统计 MUST 追踪缓存命中次数和 LLM 调用次数
- WAF2-38: 统计 MUST 追踪平均延迟
- WAF2-39: 检测记录 MUST 保留最近 100 条于内存，同时写入 `waf2_log.json` 文件
- WAF2-60: WAF2 stats MUST 新增 `llm_errors` 字段，追踪 LLM 调用失败次数。该字段 MUST 通过 `GET /waf2/stats` 和 `GET /waf2/dashboard` 接口暴露。`POST /waf2/reset` MUST 将 `llm_errors` 重置为 0。

  #### Scenario: stats 接口返回 llm_errors
  - **WHEN** 调用 `GET /waf2/stats`
  - **THEN** 响应 JSON MUST 包含 `llm_errors` 字段（整数）

  #### Scenario: reset 清零 llm_errors
  - **WHEN** 调用 `POST /waf2/reset`
  - **THEN** `stats['llm_errors']` MUST 重置为 0

### API 端点

- WAF2-40: MUST 提供 `GET /waf2/config` — 获取当前配置
- WAF2-41: MUST 提供 `POST /waf2/config` — 更新配置
- WAF2-42: MUST 提供 `POST /waf2/cache/clear` — 清除缓存
- WAF2-43: MUST 提供 `GET /waf2/stats` — 基础统计
- WAF2-44: MUST 提供 `GET /waf2/dashboard` — 完整仪表盘数据
- WAF2-45: MUST 提供 `GET /waf2/detections` — 最近 20 条检测记录
- WAF2-46: MUST 提供 `POST /waf2/reset` — 重置统计
- WAF2-47: MUST 提供 `GET /waf2/health` — 健康检查
- WAF2-48: MUST 提供 `/<path:path>` — 主代理端点（所有 HTTP 方法）

### Docker 配置

- WAF2-50: Docker MUST 通过 `host.docker.internal` 访问宿主机服务
- WAF2-51: 环境变量通用化 — WAF2 环境变量 MUST 使用通用名称，同时向后兼容旧名。

  加载优先级：
  - API Key: `LLM_API_KEY` > `QWEN_API_KEY` > 空字符串
  - Base URL: `LLM_BASE_URL` > 默认值 `https://dashscope.aliyuncs.com/compatible-mode/v1`
  - Model: `LLM_MODEL` > 默认值 `qwen-turbo`
  - Format: `LLM_FORMAT` > 默认值 `openai`

  #### Scenario: 使用新环境变量名
  - **WHEN** 设置 `LLM_API_KEY=sk-xxx`
  - **THEN** WAF2 使用 `sk-xxx` 作为 API Key

  #### Scenario: 向后兼容旧环境变量名
  - **WHEN** 未设置 `LLM_API_KEY`，但设置了 `QWEN_API_KEY=sk-old`
  - **THEN** WAF2 回退使用 `sk-old` 作为 API Key
- WAF2-52: 容器 MUST 使用 `mcp-net` bridge 网络
- WAF2-53: 容器 MUST 设置 `restart: unless-stopped`

### ConfigUpdate 模型

- WAF2-55: ConfigUpdate 模型新增 base_url 和 format — `POST /waf2/config` 端点的 `ConfigUpdate` 模型 MUST 新增可选字段 `base_url`（字符串类型）和 `format`（字符串类型，可选值 `openai`/`anthropic`/`gemini`）。收到时 MUST 更新运行时配置。

  #### Scenario: 通过 API 更新 base_url 和 format
  - **WHEN** POST `/waf2/config` 包含 `{ "base_url": "https://api.anthropic.com", "format": "anthropic" }`
  - **THEN** WAF2 更新内部 `base_url` 和 `format` 配置
  - **AND** 后续 `call_llm()` 使用 Anthropic 格式

  #### Scenario: 不传 base_url/format 时保持不变
  - **WHEN** POST `/waf2/config` 不包含 `base_url` 或 `format` 字段
  - **THEN** WAF2 保持当前配置不变

- WAF2-56: base_url 尾部斜杠处理 — `call_llm()` 拼接 URL 时 MUST 处理 `base_url` 尾部可能存在的斜杠，避免产生双斜杠。

  #### Scenario: base_url 带尾部斜杠
  - **WHEN** `base_url` 为 `https://api.deepseek.com/v1/`
  - **THEN** 实际请求 URL 为 `https://api.deepseek.com/v1/chat/completions`（无双斜杠）

  #### Scenario: base_url 不带尾部斜杠
  - **WHEN** `base_url` 为 `https://api.deepseek.com/v1`
  - **THEN** 实际请求 URL 为 `https://api.deepseek.com/v1/chat/completions`

## Scenarios

### 请求分析通过

```
Given WAF2 已启用，请求分析已启用
When  MCP Server 发送 POST /api/users { name: "张三" }
Then  LLM 分析判定为正常请求，返回 PASS
And   请求透传到目标应用
```

### 请求分析拦截（命令注入）

```
Given WAF2 已启用，请求分析已启用
When  请求 body 包含 "system('rm -rf /')"
Then  LLM 返回 "BLOCK|command_injection|检测到系统命令执行"
And   返回 403 { error: "WAF2 拦截", direction: "request", category: "command_injection", severity: "critical" }
```

### 响应分析拦截（数据泄露）

```
Given WAF2 已启用，响应分析已启用
When  目标应用响应包含明文手机号 "13800138000"
Then  LLM 返回 "BLOCK|sensitive_data_exposure|响应包含明文手机号"
And   返回 403 { error: "WAF2 拦截", direction: "response", category: "sensitive_data_exposure", severity: "high" }
```

### 缓存命中

```
Given WAF2 已启用，缓存已启用
And   相同请求在 5 分钟内已分析过（结果为 PASS）
When  再次发送相同请求
Then  直接使用缓存结果，不调用 LLM
And   请求透传到目标应用
```

### LLM 调用失败

```
Given WAF2 已启用，但 LLM API Key 无效或 API 不可达
When  收到请求
Then  call_llm() 返回 "ERROR"
And   stats['llm_errors'] 递增 1
And   请求 MUST 放行（不因 LLM 故障阻断正常业务）
And   错误 MUST 被记录到日志
```

### WAF2 禁用

```
Given WAF2 已禁用
When  任何请求到达 WAF2 代理
Then  请求直接透传到目标应用，不经过 LLM 分析
```
