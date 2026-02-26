## MODIFIED Requirements

### Requirement: 主配置结构

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
