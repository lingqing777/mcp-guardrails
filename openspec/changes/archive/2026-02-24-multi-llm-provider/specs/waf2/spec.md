## MODIFIED Requirements

### Requirement: WAF2-20 LLM Provider 通用化
WAF2 MUST 支持 3 种 API 格式的 LLM Provider：OpenAI 兼容（`openai`）、Anthropic（`anthropic`）、Google Gemini 原生（`gemini`）。`call_llm()` MUST 根据 `format` 配置字段选择对应的请求构造逻辑，不得硬编码任何厂商的 API 地址。

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

### Requirement: WAF2-21 Dashboard LLM 配置字段
用户 MUST 可在 Dashboard 配置以下 LLM 字段：Provider（预设下拉）、Base URL、Model、API Key。配置通过 MCP Hub 同步 `base_url`、`model`、`api_key`、`format` 到 WAF2。

#### Scenario: Dashboard 配置完整 LLM 参数
- **WHEN** 用户在 Dashboard 选择 Provider 为 Anthropic Claude，填写 API Key
- **THEN** MCP Hub 同步 `base_url`、`model`、`api_key`、`format: "anthropic"` 到 WAF2 的 `POST /waf2/config`
- **AND** WAF2 使用 Anthropic 格式进行后续 LLM 调用

### Requirement: WAF2-22 支持的 Provider 列表
WAF2 MUST 兼容以下 LLM Provider（不限于此列表）：

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

### Requirement: WAF2-51 环境变量通用化
WAF2 环境变量 MUST 使用通用名称，同时向后兼容旧名。

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

## ADDED Requirements

### Requirement: WAF2-55 ConfigUpdate 模型新增 base_url 和 format
`POST /waf2/config` 端点的 `ConfigUpdate` 模型 MUST 新增可选字段 `base_url`（字符串类型）和 `format`（字符串类型，可选值 `openai`/`anthropic`/`gemini`）。收到时 MUST 更新运行时配置。

#### Scenario: 通过 API 更新 base_url 和 format
- **WHEN** POST `/waf2/config` 包含 `{ "base_url": "https://api.anthropic.com", "format": "anthropic" }`
- **THEN** WAF2 更新内部 `base_url` 和 `format` 配置
- **AND** 后续 `call_llm()` 使用 Anthropic 格式

#### Scenario: 不传 base_url/format 时保持不变
- **WHEN** POST `/waf2/config` 不包含 `base_url` 或 `format` 字段
- **THEN** WAF2 保持当前配置不变

### Requirement: WAF2-56 base_url 尾部斜杠处理
`call_llm()` 拼接 URL 时 MUST 处理 `base_url` 尾部可能存在的斜杠，避免产生双斜杠。

#### Scenario: base_url 带尾部斜杠
- **WHEN** `base_url` 为 `https://api.deepseek.com/v1/`
- **THEN** 实际请求 URL 为 `https://api.deepseek.com/v1/chat/completions`（无双斜杠）

#### Scenario: base_url 不带尾部斜杠
- **WHEN** `base_url` 为 `https://api.deepseek.com/v1`
- **THEN** 实际请求 URL 为 `https://api.deepseek.com/v1/chat/completions`
