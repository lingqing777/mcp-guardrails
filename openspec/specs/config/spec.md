# Config — 配置管理

## Purpose

管理系统所有持久化配置，包括 WAF 设置、MCP Server 定义和用户凭据。
提供 API 接口供 Dashboard 读写配置，并在 MCP Hub 与 WAF2 容器之间同步配置。

层级：MCP Hub + WAF2

## Requirements

### 配置文件

- CFG-1: 系统 MUST 使用以下配置文件：

| 文件 | 用途 | 格式 |
|------|------|------|
| `config/guardrails-config.json` | 主配置（运行模式、WAF1 规则、WAF2 参数） | JSON |
| `config/mcp-servers.json` | MCP Server 定义 | JSON |
| `config/users.json` | 用户凭据（运行时生成） | JSON |

### 主配置结构

- CFG-5: `guardrails-config.json` MUST 包含以下顶级结构：
  ```
  {
    mode: "full" | "lite",
    waf1: { enabled, rules: {...} },
    waf2: { enabled, upstream, llm: { provider, format, model, apiKey, baseUrl, timeout }, features: { requestAnalysis, responseAnalysis, cache } },
    mcpHub: { port, url }
  }
  ```

  `waf2.llm.provider` 字段 MUST 支持以下 18 个预设值 + `custom`：
  `dashscope` | `openai` | `deepseek` | `grok` | `anthropic` | `gemini` | `groq` | `mistral` | `moonshot` | `zhipu` | `siliconflow` | `perplexity` | `baidu` | `doubao` | `xfyun` | `hunyuan` | `ollama` | `custom`

  `waf2.llm.format` 字段 MUST 存储 LLM API 格式（`openai` | `anthropic` | `gemini`）。默认值为 `openai`。

  `waf2.llm.baseUrl` 字段 MUST 存储 LLM Provider 的 Base URL。默认值为 DashScope URL。

  #### Scenario: 新增 Provider 预设值
  - **WHEN** 用户通过 Dashboard 选择 "Grok (xAI)" 并保存
  - **THEN** `guardrails-config.json` 中 `waf2.llm.provider` 值为 `grok`
  - **AND** `waf2.llm.format` 值为 `openai`
  - **AND** `waf2.llm.baseUrl` 值为 `https://api.x.ai/v1`

  #### Scenario: 完整 LLM 配置保存
  - **WHEN** 用户通过 Dashboard 保存 LLM 配置
  - **THEN** `guardrails-config.json` 中 `waf2.llm` 包含 `provider`、`format`、`model`、`apiKey`、`baseUrl`、`timeout` 六个字段
- CFG-6: `mode: "full"` 表示 WAF1 + WAF2 双层检测
- CFG-7: `mode: "lite"` 表示仅 WAF2 LLM 检测

### 优先级

- CFG-10: 配置优先级 MUST 为：环境变量 > 配置文件 > 默认值
- CFG-11: 关键环境变量 MUST 包括：
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

### 配置加载

- CFG-15: 配置加载 MUST 使用深度合并策略（保留用户已有配置）
- CFG-16: 配置文件不存在时 MUST 使用默认值，不报错
- CFG-17: 配置文件格式错误时 MUST 记录错误并回退到默认值

### 配置保存

- CFG-20: 配置变更 MUST 写入对应的 JSON 文件
- CFG-21: 保存时 MUST 使用 JSON.stringify 缩进 2 空格格式化
- CFG-22: 写入失败 MUST 记录错误日志

### 配置同步

- CFG-25: WAF2 配置同步 — Dashboard 更新 WAF2 相关配置时 MUST 通过 HTTP 同步到 WAF2 容器。`syncToWaf2()` MUST 传递以下字段到 `POST /waf2/config`：
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
- CFG-26: 同步端点为 `POST /waf2/config`
- CFG-27: 同步失败 MUST 返回错误信息给用户，不静默失败

### WAF1 配置应用

- CFG-30: WAF1 相关配置变更 MUST 通过 `applyWaf1Config()` 实时应用到 WAF1 运行时
- CFG-31: 规则启用/禁用 MUST 即时生效，不需要重启

### API 端点

- CFG-35: MUST 提供 `GET /api/config` — 读取当前完整配置
- CFG-36: MUST 提供 `POST /api/config` — 更新配置（深度合并）
- CFG-37: MUST 提供 `POST /api/config/sync-waf2` — 手动触发 WAF2 配置同步

### Docker 环境变量

- CFG-40: Docker 环境变量通用化 — `docker-compose.yml` MUST 使用通用环境变量名传递 LLM 配置到 WAF2 容器：
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

- CFG-41: .env 文件通用化 — `.env` 和 `.env.example` 文件 MUST 使用通用变量名，并包含注释说明支持的 Provider。

  #### Scenario: .env.example 内容
  - **WHEN** 用户查看 `.env.example`
  - **THEN** 文件包含 `LLM_API_KEY=`、`LLM_BASE_URL=`、`LLM_MODEL=`、`LLM_FORMAT=` 四个通用变量
  - **AND** 包含注释说明支持的 Provider 和 Base URL 示例
  - **AND** `LLM_FORMAT` 注释说明可选值为 openai / anthropic / gemini

## Scenarios

### 读取配置

```
Given 用户已登录
When  Dashboard 请求 GET /api/config
Then  返回当前完整配置（合并了环境变量覆盖后的最终值）
```

### 更新 WAF1 规则

```
Given 用户在 Dashboard WAF1 Tab 关闭 SQL 注入规则
When  提交 POST /api/config { waf1: { rules: { sqlInjection: false } } }
Then  配置深度合并，只修改 sqlInjection，其他规则不变
And   写入 guardrails-config.json
And   applyWaf1Config() 实时应用
And   WAF1 立即停止检测 SQL 注入
```

### 更新 WAF2 LLM 配置

```
Given 用户在 Dashboard 修改 LLM API Key
When  提交 POST /api/config { waf2: { llm: { apiKey: "sk-new-key" } } }
Then  配置写入 guardrails-config.json
And   自动同步到 WAF2 容器（POST /waf2/config）
And   WAF2 使用新的 API Key 进行后续分析
```

### 环境变量覆盖

```
Given 环境变量 TARGET_URL=http://example.com:3000
And   guardrails-config.json 中 waf2.upstream=http://host.docker.internal:3000
When  系统加载配置
Then  waf2.upstream 最终值为 http://example.com:3000（环境变量优先）
```

### 模式切换

```
Given 当前模式为 full（WAF1 + WAF2）
When  用户切换到 lite 模式
Then  WAF1 被禁用，仅 WAF2 LLM 检测生效
And   配置写入 guardrails-config.json
```
