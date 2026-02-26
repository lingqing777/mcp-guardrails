## MODIFIED Requirements

### Requirement: CFG-5 主配置结构
`guardrails-config.json` MUST 包含以下顶级结构：
```
{
  mode: "full" | "lite",
  waf1: { enabled, rules: {...} },
  waf2: { enabled, upstream, llm: { provider, format, model, apiKey, baseUrl, timeout }, features: { requestAnalysis, responseAnalysis, cache } },
  mcpHub: { port, url }
}
```

`waf2.llm.baseUrl` 字段 MUST 存储 LLM Provider 的 Base URL（如 `https://dashscope.aliyuncs.com/compatible-mode/v1`）。默认值为 DashScope URL，确保向后兼容。

`waf2.llm.format` 字段 MUST 存储 LLM API 格式（`openai` | `anthropic` | `gemini`）。默认值为 `openai`，确保向后兼容。

#### Scenario: 新增 baseUrl 字段默认值
- **WHEN** 配置文件中 `waf2.llm` 不包含 `baseUrl` 字段
- **THEN** 系统使用默认值 `https://dashscope.aliyuncs.com/compatible-mode/v1`
- **AND** 不影响现有用户的 DashScope 配置

#### Scenario: 完整 LLM 配置保存
- **WHEN** 用户通过 Dashboard 保存 LLM 配置
- **THEN** `guardrails-config.json` 中 `waf2.llm` 包含 `provider`、`format`、`model`、`apiKey`、`baseUrl`、`timeout` 六个字段

### Requirement: CFG-11 关键环境变量
配置加载 MUST 识别以下环境变量：
- `TARGET_URL` — 覆盖 waf2.upstream
- `LLM_API_KEY` — LLM API Key（新名，优先）
- `QWEN_API_KEY` — LLM API Key（旧名，向后兼容回退）
- `LLM_BASE_URL` — LLM Base URL（新增）
- `LLM_MODEL` — LLM 模型名
- `LLM_FORMAT` — LLM API 格式（openai/anthropic/gemini，默认 openai）
- `PORT` — MCP Hub 端口（默认 4000）
- `WAF2_URL` — WAF2 端点（默认 localhost:8081）
- `DISABLE_AUTH` — 设为 'true' 禁用认证

API Key 加载优先级：`LLM_API_KEY` > `QWEN_API_KEY` > 配置文件 > 空字符串

#### Scenario: MCP Hub 使用新环境变量名
- **WHEN** 设置 `LLM_API_KEY=sk-new`
- **THEN** MCP Hub 配置加载使用 `sk-new` 作为 LLM API Key

#### Scenario: MCP Hub 向后兼容旧环境变量名
- **WHEN** 未设置 `LLM_API_KEY`，但设置了 `QWEN_API_KEY=sk-old`
- **THEN** MCP Hub 回退使用 `sk-old` 作为 LLM API Key

#### Scenario: LLM_BASE_URL 环境变量覆盖
- **WHEN** 设置 `LLM_BASE_URL=https://api.deepseek.com/v1`
- **THEN** MCP Hub 配置中 `waf2.llm.baseUrl` 使用环境变量值

### Requirement: CFG-25 WAF2 配置同步
Dashboard 更新 WAF2 相关配置时 MUST 通过 HTTP 同步到 WAF2 容器。`syncToWaf2()` MUST 传递以下字段到 `POST /waf2/config`：
- `api_key` — LLM API Key
- `model` — LLM Model
- `base_url` — LLM Base URL（新增）
- `format` — LLM API 格式（新增）
- `upstream` — 目标应用 URL
- `enabled` — WAF2 启用状态
- `request_analysis` / `response_analysis` — 检测开关
- `cache_enabled` — 缓存开关

#### Scenario: 同步包含 base_url
- **WHEN** Dashboard 提交 WAF2 配置变更
- **THEN** `syncToWaf2()` 向 `POST /waf2/config` 发送的 payload 包含 `base_url` 字段
- **AND** WAF2 接收并更新 base_url

#### Scenario: base_url 未配置时同步默认值
- **WHEN** 配置中未设置 `waf2.llm.baseUrl`
- **THEN** `syncToWaf2()` 发送默认值 `https://dashscope.aliyuncs.com/compatible-mode/v1`

## ADDED Requirements

### Requirement: CFG-40 Docker 环境变量通用化
`docker-compose.yml` MUST 使用通用环境变量名传递 LLM 配置到 WAF2 容器：
- `LLM_API_KEY` — 从 `${LLM_API_KEY:-${QWEN_API_KEY:-}}` 加载（向后兼容）
- `LLM_BASE_URL` — 从 `${LLM_BASE_URL:-}` 加载（新增）
- `LLM_MODEL` — 保持 `${LLM_MODEL:-qwen-turbo}`
- `LLM_FORMAT` — 从 `${LLM_FORMAT:-openai}` 加载（新增）

#### Scenario: docker-compose 向后兼容
- **WHEN** 用户 `.env` 文件中仅设置了 `QWEN_API_KEY`
- **THEN** Docker 容器内 WAF2 仍可正确读取 API Key

#### Scenario: docker-compose 使用新变量名
- **WHEN** 用户 `.env` 文件中设置了 `LLM_API_KEY`
- **THEN** Docker 容器内 WAF2 使用 `LLM_API_KEY` 的值

### Requirement: CFG-41 .env 文件通用化
`.env` 和 `.env.example` 文件 MUST 使用通用变量名，并包含注释说明支持的 Provider。

#### Scenario: .env.example 内容
- **WHEN** 用户查看 `.env.example`
- **THEN** 文件包含 `LLM_API_KEY=`、`LLM_BASE_URL=`、`LLM_MODEL=`、`LLM_FORMAT=` 四个通用变量
- **AND** 包含注释说明支持的 Provider 和 Base URL 示例
- **AND** `LLM_FORMAT` 注释说明可选值为 openai / anthropic / gemini
