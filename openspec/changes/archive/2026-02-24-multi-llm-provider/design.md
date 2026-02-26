## Context

WAF2 的 `call_llm()` 函数硬编码了 DashScope API 地址 (`https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions`)，环境变量名绑定千问 (`QWEN_API_KEY`)，Dashboard 配置面板只有 API Key 输入框且标注 "(Qwen DashScope)"。用户无法切换到其他 LLM 厂商。

当前数据流：

```
Dashboard → POST /api/config/waf2 { llm: { apiKey } }
         → config.js syncToWaf2() → POST /waf2/config { api_key, model }
         → waf2_proxy.py call_llm() → POST QWEN_API_URL (硬编码)
```

经调研，全球主流 LLM 厂商分为 3 种 API 格式：

```
┌──────────────┬────────────────────────────────────────────────┐
│ format       │ 厂商                                           │
├──────────────┼────────────────────────────────────────────────┤
│ openai       │ OpenAI, DashScope, DeepSeek, Moonshot, GLM,   │
│              │ SiliconFlow, 百度文心(千帆), 豆包(火山), Ollama │
├──────────────┼────────────────────────────────────────────────┤
│ anthropic    │ Anthropic Claude                               │
├──────────────┼────────────────────────────────────────────────┤
│ gemini       │ Google Gemini (原生格式，官方推荐优先使用)       │
└──────────────┴────────────────────────────────────────────────┘
```

## Goals / Non-Goals

**Goals:**
- `call_llm()` 根据 `format` 字段分 3 条代码路径（openai / anthropic / gemini）
- 配置链路完整传递 `base_url` + `format`：Dashboard UI → MCP Hub config → WAF2 config
- Dashboard 提供 12 个 Provider 预设 + 自定义，选择后自动填充 base URL、推荐模型、format
- Dashboard Provider 切换时有视觉差异：格式标签（带颜色）、获取 Key 链接、API Key 字段动态显隐
- 环境变量通用化 (`LLM_API_KEY`)，向后兼容旧名 (`QWEN_API_KEY`)
- 支持自定义 Base URL + 手选 format（用于代理等第三方转发）

**Non-Goals:**
- 不引入 LiteLLM 或其他 LLM 统一库
- 不新增 Provider 基类 / 工厂模式 / 适配器抽象（只用 if/elif 分支）
- 不做 LLM 调用的流式输出、Token 计数、Prompt Cache
- 不修改 WAF1 逻辑

## Decisions

### Decision 1: 3 种 format 分支，不需要 provider 抽象

**选择**: WAF2 新增 `format` 字段（`"openai"` | `"anthropic"` | `"gemini"`），`call_llm()` 按 format 走不同的请求构造逻辑。

**备选方案**:
- A) 引入 Provider 工厂 + 适配器模式（DeepAudit 方案）→ 过度工程
- B) 只支持 OpenAI 兼容 → Claude 和 Gemini 原生无法支持
- C) 3 个 if 分支 → 最小改动，覆盖所有主流厂商

**理由**: WAF2 只做一件事：发 prompt，拿 PASS/BLOCK。3 种格式的差异仅在 URL 拼法、Header、响应解析上，各十来行代码，不值得抽象。

3 种格式的差异对比：

| | openai | anthropic | gemini |
|---|---|---|---|
| URL | `{base_url}/chat/completions` | `{base_url}/v1/messages` | `{base_url}/v1beta/models/{model}:generateContent` |
| 认证 | `Authorization: Bearer <key>` | `x-api-key: <key>` | `x-goog-api-key: <key>` |
| 额外 Header | 无 | `anthropic-version: 2023-06-01` | 无 |
| 请求体 messages | `[{role, content}]` | `[{role, content}]` | `[{role, parts: [{text}]}]` |
| 响应取值 | `choices[0].message.content` | `content[0].text` | `candidates[0].content.parts[0].text` |
| model 位置 | body 里 | body 里 | URL 路径里 |

### Decision 2: Provider 预设映射表（前端 JS）

**选择**: `LLM_PROVIDERS` 映射表扩展为 12 + 自定义，每个条目包含 `format`、`baseUrl`、`model`、`keyUrl`（获取 Key 链接）。

```
LLM_PROVIDERS = {
  dashscope:   { label: '通义千问 (DashScope)', format: 'openai',     baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-turbo',                 keyUrl: 'https://bailian.console.aliyun.com/#/api-key' },
  openai:      { label: 'OpenAI',               format: 'openai',     baseUrl: 'https://api.openai.com/v1',                       model: 'gpt-4o-mini',                keyUrl: 'https://platform.openai.com/api-keys' },
  deepseek:    { label: 'DeepSeek',             format: 'openai',     baseUrl: 'https://api.deepseek.com/v1',                     model: 'deepseek-chat',              keyUrl: 'https://platform.deepseek.com/api_keys' },
  anthropic:   { label: 'Anthropic Claude',     format: 'anthropic',  baseUrl: 'https://api.anthropic.com',                       model: 'claude-sonnet-4-5-20250929', keyUrl: 'https://console.anthropic.com/settings/keys' },
  gemini:      { label: 'Google Gemini',        format: 'gemini',     baseUrl: 'https://generativelanguage.googleapis.com',       model: 'gemini-2.5-flash',           keyUrl: 'https://aistudio.google.com/apikey' },
  moonshot:    { label: 'Moonshot (Kimi)',       format: 'openai',     baseUrl: 'https://api.moonshot.cn/v1',                      model: 'moonshot-v1-8k',             keyUrl: 'https://platform.moonshot.cn/console/api-keys' },
  zhipu:       { label: '智谱 AI (GLM)',         format: 'openai',     baseUrl: 'https://open.bigmodel.cn/api/paas/v4',            model: 'glm-4-flash',                keyUrl: 'https://open.bigmodel.cn/usercenter/apikeys' },
  siliconflow: { label: 'SiliconFlow',          format: 'openai',     baseUrl: 'https://api.siliconflow.cn/v1',                   model: 'deepseek-ai/DeepSeek-V3',    keyUrl: 'https://cloud.siliconflow.cn/account/ak' },
  baidu:       { label: '百度文心',              format: 'openai',     baseUrl: 'https://qianfan.baidubce.com/v2',                 model: 'ernie-4.0-8k',               keyUrl: 'https://console.bce.baidu.com/iam/#/iam/apikey' },
  doubao:      { label: '豆包 (火山引擎)',       format: 'openai',     baseUrl: 'https://ark.cn-beijing.volces.com/api/v3',        model: 'doubao-1.5-pro-32k',         keyUrl: 'https://console.volcengine.com/ark/region:ark+cn-beijing/apiKey' },
  ollama:      { label: 'Ollama (本地)',          format: 'openai',     baseUrl: 'http://localhost:11434/v1',                       model: 'llama3',                     keyUrl: '' },
  custom:      { label: '自定义',                 format: 'openai',     baseUrl: '',                                                model: '',                           keyUrl: '' }
}
```

### Decision 3: 环境变量向后兼容

**选择**: 新名 `LLM_API_KEY`，加载时优先 `LLM_API_KEY`，回退到 `QWEN_API_KEY`。

WAF2 Python:
```python
self.api_key = os.environ.get("LLM_API_KEY", os.environ.get("QWEN_API_KEY", ""))
self.base_url = os.environ.get("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
self.model = os.environ.get("LLM_MODEL", "qwen-turbo")
self.format = os.environ.get("LLM_FORMAT", "openai")
```

MCP Hub Node.js:
```javascript
config.waf2.llm.apiKey = process.env.LLM_API_KEY || process.env.QWEN_API_KEY || ''
```

### Decision 4: 配置结构扩展

**选择**: `guardrails-config.json` 的 `waf2.llm` 新增 `baseUrl` 和 `format` 字段。

```json
"llm": {
  "provider": "dashscope",
  "format": "openai",
  "model": "qwen-turbo",
  "apiKey": "",
  "baseUrl": "https://dashscope.aliyuncs.com/compatible-mode/v1",
  "timeout": 30000
}
```

`syncToWaf2()` 传递 `base_url` 和 `format` 字段。WAF2 的 `ConfigUpdate` 模型和 `update_config` 端点新增 `base_url` 和 `format`。

### Decision 5: Dashboard UI 交互 — 动态视觉差异

**选择**: Provider 切换时，配置区域呈现视觉差异化，通过以下元素实现：

1. **格式标签**: Provider 下拉下方显示格式 badge，颜色随 format 变化
   - openai → 蓝色 `OpenAI 兼容`
   - anthropic → 橙色 `Anthropic`
   - gemini → 绿色 `Gemini 原生`

2. **获取 Key 链接**: 每个 Provider 显示对应平台的 API Key 申请链接（`📎 获取 Key → ...`）

3. **API Key 字段动态显隐**: Ollama 时 API Key 行淡出隐藏，显示 "本地部署，无需 API Key" 提示

4. **格式选择器**: 仅在选择 "自定义" 时显示三选一单选组（OpenAI 兼容 / Anthropic / Gemini 原生）

5. **过渡动画**: 所有动态变化使用 `transition: all 0.3s ease` 平滑过渡，字段显隐用 opacity + max-height 动画

full 模式和 lite 模式共用同一套 LLM 配置 UI 结构。

## Risks / Trade-offs

**[默认值变更]** → 现有用户如果已经在用 DashScope，升级后 config 会新增 `baseUrl` 和 `format` 字段。默认值设为 DashScope / openai，不破坏现有行为。

**[Gemini 原生格式稳定性]** → Gemini 原生 API 使用 `v1beta` 版本，Google 不保证向后兼容。但这是 Google 推荐的调用方式，且 WAF2 只用最基础的 generateContent，风险可控。

**[Ollama 无需 API Key]** → Ollama 不需要 API Key 但需要 base URL。Dashboard UI 中 Ollama 选中时隐藏 API Key 字段。

**[自定义 format 选择]** → 自定义模式下用户需要手选 format。默认选中 "OpenAI 兼容"，覆盖 99% 的自定义代理场景。
