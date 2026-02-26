## Why

WAF2 的 LLM 调用硬编码了阿里 DashScope 的 API 地址、环境变量名 (`QWEN_API_KEY`) 和默认模型 (`qwen-turbo`)。用户无法在 Dashboard 中切换到 OpenAI、DeepSeek、Moonshot、GLM 等其他 OpenAI 兼容格式的 LLM 厂商。作为信安作品赛项目，答辩时裁判可能使用不同厂商的 Key，需要开箱即用的多厂商支持。

## What Changes

- WAF2 Python 端新增 `base_url` 动态配置字段，`call_llm()` 使用 `config.base_url + /chat/completions` 替代硬编码的 `QWEN_API_URL`
- WAF2 环境变量从 `QWEN_API_KEY` 改为 `LLM_API_KEY`（向后兼容旧名）
- WAF2 `ConfigUpdate` 模型和 `/waf2/config` 端点新增 `base_url` 字段
- MCP Hub config 结构新增 `baseUrl` 字段，`syncToWaf2()` 补传 `base_url`
- MCP Hub 环境变量从 `QWEN_API_KEY` 改为 `LLM_API_KEY`（向后兼容旧名）
- Dashboard 配置面板新增 Provider 下拉选择（预设 7 个厂商 + 自定义），选择后自动填充 Base URL 和推荐模型
- Dashboard 配置面板新增 Base URL 和 Model 输入框
- Dashboard 去除所有 "Qwen DashScope" 硬编码文案
- `docker-compose.yml` 环境变量改为 `LLM_API_KEY`（向后兼容）
- `.env` / `.env.example` 变量名通用化

## Capabilities

### New Capabilities

无。不引入新能力模块，仅通用化现有 LLM 调用机制。

### Modified Capabilities

- `waf2`: LLM 调用从硬编码 DashScope 改为可配置 base_url，环境变量通用化
- `dashboard`: 配置面板新增 Provider 选择、Base URL、Model 配置 UI
- `config`: 配置结构新增 `baseUrl` 字段，环境变量名通用化

## Impact

- **修改文件**：
  - `waf2/waf2_proxy.py` — LLM 调用逻辑、配置模型、环境变量
  - `mcp-hub/src/api/config.js` — 默认配置、环境变量加载、syncToWaf2
  - `mcp-hub/src/dashboard/index.html` — 配置面板 UI（两处：full 模式和 lite 模式）
  - `mcp-hub/src/dashboard/app.js` — applyConfig() 补传 provider/baseUrl/model
  - `config/guardrails-config.json` — 新增 baseUrl 字段
  - `docker-compose.yml` — 环境变量名
  - `.env` / `.env.example` — 变量名和注释
  - `README.md` — 去除 Qwen 特定描述
- **API**：`POST /waf2/config` 新增 `base_url` 字段（非破坏性，可选字段）
- **Docker**：`docker-compose.yml` 环境变量改名（兼容旧名，非破坏性）
- **路由**：无新路由
- **Dashboard 刷新**：无影响，配置操作是手动触发
