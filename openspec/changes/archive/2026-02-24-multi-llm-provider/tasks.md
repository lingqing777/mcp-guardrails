## 1. WAF2 Python 端 — 环境变量与配置模型

- [x] 1.1 `waf2/waf2_proxy.py` — 将 `self.api_key = os.environ.get("QWEN_API_KEY", "")` 改为 `self.api_key = os.environ.get("LLM_API_KEY", os.environ.get("QWEN_API_KEY", ""))`
- [x] 1.2 `waf2/waf2_proxy.py` — 新增 `self.base_url = os.environ.get("LLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")`
- [x] 1.3 `waf2/waf2_proxy.py` — 将 `self.model` 的 `os.environ.get("QWEN_MODEL", ...)` 改为 `os.environ.get("LLM_MODEL", "qwen-turbo")`
- [x] 1.4 `waf2/waf2_proxy.py` — 删除全局常量 `QWEN_API_URL`
- [x] 1.5 `waf2/waf2_proxy.py` — `ConfigUpdate` Pydantic 模型新增 `base_url: Optional[str] = None`
- [x] 1.6 `waf2/waf2_proxy.py` — `update_config` 端点新增处理 `config.base_url`：非 None 时更新 `waf2_config.base_url`

## 2. WAF2 Python 端 — call_llm() 动态 URL

- [x] 2.1 `waf2/waf2_proxy.py` — `call_llm()` 将硬编码 `QWEN_API_URL` 替换为 `self.base_url.rstrip("/") + "/chat/completions"`
- [x] 2.2 `waf2/waf2_proxy.py` — `call_llm()` 当 `self.api_key` 为空时，请求 Header 中不包含 `Authorization` 字段（支持 Ollama 无 Key 场景）

## 3. MCP Hub 配置层 — 默认值与环境变量

- [x] 3.1 `mcp-hub/src/api/config.js` — 默认配置 `waf2.llm` 新增 `baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1'`
- [x] 3.2 `mcp-hub/src/api/config.js` — 默认配置 `waf2.llm.provider` 从 `'qwen'` 改为 `'dashscope'`（与前端预设映射表 key 一致）
- [x] 3.3 `mcp-hub/src/api/config.js` — 环境变量加载改为 `process.env.LLM_API_KEY || process.env.QWEN_API_KEY || ''`
- [x] 3.4 `mcp-hub/src/api/config.js` — 新增环境变量加载 `LLM_BASE_URL`（如存在则覆盖配置文件中的 baseUrl）

## 4. MCP Hub 配置层 — syncToWaf2() 补传字段

- [x] 4.1 `mcp-hub/src/api/config.js` — `syncToWaf2()` 新增传递 `base_url: config.waf2.llm.baseUrl` 到 WAF2
- [x] 4.2 `mcp-hub/src/api/config.js` — POST `/api/config/waf2` 处理函数中，接收 `llm.baseUrl` 并写入配置

## 5. Dashboard HTML — LLM 配置 UI 重构

- [x] 5.1 `mcp-hub/src/dashboard/index.html` — full 模式配置面板：将 API Key 单输入框替换为 Provider 下拉 + Base URL 输入 + Model 输入 + API Key 输入（四字段布局）
- [x] 5.2 `mcp-hub/src/dashboard/index.html` — lite 模式配置面板：同 5.1，将 API Key 单输入框替换为四字段布局
- [x] 5.3 `mcp-hub/src/dashboard/index.html` — WAF2 Tab 面板：N/A（当前无 LLM 配置输入）
- [x] 5.4 `mcp-hub/src/dashboard/index.html` — 移除所有 "(Qwen DashScope)" 文案标注

## 6. Dashboard JS — Provider 预设映射与自动填充

- [x] 6.1 `mcp-hub/src/dashboard/app.js` — 在文件顶部新增 `LLM_PROVIDERS` 映射表（8 个条目：dashscope/openai/deepseek/moonshot/zhipu/siliconflow/ollama/custom）
- [x] 6.2 `mcp-hub/src/dashboard/app.js` — 新增 `onProviderChange(selectEl, section)` 函数：根据选中 Provider 自动填充同组的 Base URL 和 Model 输入框；选择 Ollama 时修改 API Key 的 placeholder
- [x] 6.3 `mcp-hub/src/dashboard/app.js` — 为 full/lite/WAF2 三处 Provider 下拉绑定 `onchange` 事件

## 7. Dashboard JS — applyConfig() 补传字段

- [x] 7.1 `mcp-hub/src/dashboard/app.js` — `applyConfig()` 中读取 Provider/Base URL/Model 值，补充到 `waf2.llm` 配置对象
- [x] 7.2 `mcp-hub/src/dashboard/app.js` — 配置加载回显时（`loadConfig` 或初始化时），根据配置中的 `provider`/`baseUrl`/`model` 回填 UI 输入框

## 8. 配置文件与 Docker

- [x] 8.1 `config/guardrails-config.json` — `waf2.llm` 新增 `"baseUrl": "https://dashscope.aliyuncs.com/compatible-mode/v1"`，`provider` 改为 `"dashscope"`
- [x] 8.2 `docker-compose.yml` — `QWEN_API_KEY` 改为 `LLM_API_KEY=${LLM_API_KEY:-${QWEN_API_KEY:-}}`，新增 `LLM_BASE_URL=${LLM_BASE_URL:-}`
- [x] 8.3 `.env` — 变量名改为 `LLM_API_KEY=`，新增 `LLM_BASE_URL=`，新增 `LLM_MODEL=`，保留注释说明

---

## 10. WAF2 Python 端 — format 字段与多格式 call_llm()

- [x] 10.1 `waf2/waf2_proxy.py` — WAF2Config 新增 `self.format = os.environ.get("LLM_FORMAT", "openai")`
- [x] 10.2 `waf2/waf2_proxy.py` — ConfigUpdate 模型新增 `format: Optional[str] = None`，update_config 端点处理 format
- [x] 10.3 `waf2/waf2_proxy.py` — `call_llm()` 重构为按 format 分支：openai（当前逻辑）/ anthropic（`/v1/messages` + `x-api-key` + `anthropic-version` Header，响应取 `content[0].text`）/ gemini（URL 含 model 路径 + `x-goog-api-key` Header + contents/parts 请求体，响应取 `candidates[0].content.parts[0].text`）
- [x] 10.4 `waf2/waf2_proxy.py` — get_config 端点返回值新增 `format` 字段

## 11. MCP Hub 配置层 — format 字段传递

- [x] 11.1 `mcp-hub/src/api/config.js` — 默认配置 `waf2.llm` 新增 `format: 'openai'`
- [x] 11.2 `mcp-hub/src/api/config.js` — `syncToWaf2()` payload 新增 `format: waf2Config.llm?.format`
- [x] 11.3 `mcp-hub/src/api/config.js` — POST `/api/config/waf2` 处理函数接收 `llm.format` 并写入配置
- [x] 11.4 `config/guardrails-config.json` — `waf2.llm` 新增 `"format": "openai"`

## 12. Dashboard JS — Provider 预设扩展（12 + 自定义）

- [x] 12.1 `mcp-hub/src/dashboard/app.js` — `LLM_PROVIDERS` 扩展：新增 `format` 和 `keyUrl` 字段，新增 anthropic/gemini/baidu/doubao 四个 Provider 条目
- [x] 12.2 `mcp-hub/src/dashboard/index.html` — full/lite 两处 Provider `<select>` 新增 anthropic/gemini/baidu/doubao 四个 `<option>`

## 13. Dashboard HTML — 动态 UI 元素

- [x] 13.1 `mcp-hub/src/dashboard/index.html` — full/lite 两处 Provider 下拉下方新增：格式标签 `<span id="cfg-format-badge">` + 获取 Key 链接 `<a id="cfg-key-link">`
- [x] 13.2 `mcp-hub/src/dashboard/index.html` — full/lite 两处新增 API Key 隐藏时的占位提示 `<div id="cfg-apikey-hint">` （"本地部署，无需 API Key"）
- [x] 13.3 `mcp-hub/src/dashboard/index.html` — full/lite 两处新增自定义格式选择器 `<div id="cfg-format-selector">`，包含 3 个 radio：OpenAI 兼容 / Anthropic / Gemini 原生（默认隐藏，选"自定义"时显示）

## 14. Dashboard CSS — 格式标签样式与动画

- [x] 14.1 `mcp-hub/src/dashboard/styles.css` — 新增 `.format-badge` 基础样式（圆角小标签、12px 字号、行内块）
- [x] 14.2 `mcp-hub/src/dashboard/styles.css` — 新增 3 种格式标签颜色：`.format-badge.openai`（蓝色 #58a6ff）、`.format-badge.anthropic`（橙色 #f0883e）、`.format-badge.gemini`（绿色 #3fb950）
- [x] 14.3 `mcp-hub/src/dashboard/styles.css` — 新增 `.llm-apikey-row` 过渡动画：`transition: opacity 0.3s ease, max-height 0.3s ease`，隐藏时 `opacity: 0; max-height: 0; overflow: hidden`
- [x] 14.4 `mcp-hub/src/dashboard/styles.css` — 新增 `.format-selector` 样式（三选一 radio 组，默认隐藏，同上过渡动画），新增 `.key-link` 样式（小字号链接，带 hover 下划线）

## 15. Dashboard JS — onProviderChange() 增强

- [x] 15.1 `mcp-hub/src/dashboard/app.js` — `onProviderChange()` 增强：根据 provider.format 更新格式标签文字和颜色 class
- [x] 15.2 `mcp-hub/src/dashboard/app.js` — `onProviderChange()` 增强：根据 provider.keyUrl 更新获取 Key 链接（无 keyUrl 时隐藏）
- [x] 15.3 `mcp-hub/src/dashboard/app.js` — `onProviderChange()` 增强：Ollama 时隐藏 API Key 行 + 显示占位提示，其他 Provider 时恢复
- [x] 15.4 `mcp-hub/src/dashboard/app.js` — `onProviderChange()` 增强：选"自定义"时显示格式选择器，选预设时隐藏
- [x] 15.5 `mcp-hub/src/dashboard/app.js` — `applyConfig()` 增强：读取当前 format（预设 Provider 从映射表取，自定义从 radio 取），传入 `llm.format`
- [x] 15.6 `mcp-hub/src/dashboard/app.js` — `initConfigPanel()` 增强：配置回填时同步更新格式标签、Key 链接、API Key 显隐、格式选择器状态

## 16. Docker 环境变量补充

- [x] 16.1 `docker-compose.yml` — 新增 `LLM_FORMAT=${LLM_FORMAT:-openai}` 环境变量
- [x] 16.2 `.env` / `.env.example` — 新增 `LLM_FORMAT=` 变量及注释说明（openai / anthropic / gemini）

## 17. 验证

- [ ] 17.1 验证 WAF2 启动时使用 `LLM_BASE_URL`、`LLM_API_KEY`、`LLM_FORMAT` 环境变量
- [ ] 17.2 验证 Dashboard Provider 下拉选择后 Base URL、Model 自动填充，格式标签和 Key 链接正确切换
- [ ] 17.3 验证选择 Ollama 时 API Key 字段隐藏，选其他 Provider 时恢复
- [ ] 17.4 验证选择"自定义"时格式选择器出现，选预设 Provider 时隐藏
- [ ] 17.5 验证 Dashboard 保存配置后 WAF2 收到 `base_url` + `format` 字段
- [ ] 17.6 验证 format=anthropic 时 call_llm() 使用 `/v1/messages` + `x-api-key` Header
- [ ] 17.7 验证 format=gemini 时 call_llm() 使用 `/v1beta/models/{model}:generateContent` + `x-goog-api-key` Header
- [ ] 17.8 验证 Dashboard 中无 "Qwen DashScope" 硬编码文案
- [ ] 17.9 验证向后兼容：仅设置 `QWEN_API_KEY` 时 WAF2 仍能正常工作（format 默认 openai）
