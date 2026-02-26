## 1. LLM_PROVIDERS 数据扩展 (app.js)

- [x] 1.1 在 `mcp-hub/src/dashboard/app.js` 中将 `LLM_PROVIDERS` 从 12 项扩展到 19 项（18 预设 + custom），新增 grok/groq/mistral/perplexity/xfyun/hunyuan 条目，每项包含 label/format/baseUrl/model/keyUrl 五个字段
- [x] 1.2 调整 `LLM_PROVIDERS` 对象中 key 的排列顺序为：dashscope → openai → deepseek → grok → anthropic → gemini → groq → mistral → moonshot → zhipu → siliconflow → perplexity → baidu → doubao → xfyun → hunyuan → ollama → custom

## 2. HTML 卡片网格结构 (index.html)

- [x] 2.1 在 `mcp-hub/src/dashboard/index.html` 配置 Tab（Full 模式）中，将 Provider `<select>` 替换为 `.provider-card-grid` 容器，内含 19 个 `.provider-card` 元素（每个带 `data-provider` 和 `data-format` 属性）
- [x] 2.2 在配置 Tab（Full 模式）卡片网格下方添加 `.provider-config-panel` 滑出面板，包含 Base URL、Model、API Key 输入字段 + 获取 Key 链接 + 协议标签 + format radio（自定义用）+ Ollama 提示
- [x] 2.3 在 Lite 模式中同样替换 Provider `<select>` 为 `.provider-card-grid` + `.provider-config-panel`（ID 带 `-lite` 后缀）
- [x] 2.4 移除旧的 Provider `<select>` 元素和已废弃的 `.provider-meta` / `#cfg-format-badge` / `#cfg-key-link` 等 HTML 结构

## 3. CSS 卡片样式 (styles.css)

- [x] 3.1 在 `mcp-hub/src/dashboard/styles.css` 中新增 `.provider-card-grid` 样式：`display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px`
- [x] 3.2 新增 `.provider-card` 基础样式：背景 `var(--bg-secondary)`、圆角 6px、padding 12px 10px、border 1px solid `var(--border)`、cursor pointer、`border-top: 3px solid transparent`、transition
- [x] 3.3 新增 `.provider-card` 三种 format 色条：`.provider-card[data-format="openai"]` border-top-color `#58a6ff`、`.provider-card[data-format="anthropic"]` border-top-color `#f0883e`、`.provider-card[data-format="gemini"]` border-top-color `#3fb950`
- [x] 3.4 新增 `.provider-card:hover` 样式：border-color 变亮、`transform: translateY(-1px)`、轻微 box-shadow
- [x] 3.5 新增 `.provider-card.selected` 样式：border-color 对应 format 色、box-shadow 外发光（参考现有 `.mode-card.selected` 的 glow 效果）、背景微亮
- [x] 3.6 新增 `.provider-config-panel` 样式：`max-height: 0; opacity: 0; overflow: hidden; transition: max-height 0.3s ease, opacity 0.3s ease`；`.provider-config-panel.open` 为 `max-height: 300px; opacity: 1`
- [x] 3.7 移除旧的 `.provider-meta`、`.format-badge`、`.key-link`、`.apikey-hint`、`.format-selector`、`.format-radio` 样式（已被卡片 UI 取代）

## 4. JS 交互逻辑 (app.js)

- [x] 4.1 新增 `onProviderCardClick(card, section)` 函数：处理卡片点击 → 切换 `.selected` class → 读取 `data-provider` → 从 LLM_PROVIDERS 获取配置 → 填充配置面板字段 → 展开 `.provider-config-panel`
- [x] 4.2 在 `onProviderCardClick` 中实现 Ollama 特殊逻辑：隐藏 API Key 行 + 显示"本地部署"提示
- [x] 4.3 在 `onProviderCardClick` 中实现自定义 Provider 特殊逻辑：显示 format radio + 清空 Base URL/Model
- [x] 4.4 重写 `applyConfig()` 函数中 provider 读取逻辑：从选中的 `.provider-card.selected` 的 `data-provider` 属性读取，替代旧的 `<select>` value 读取
- [x] 4.5 重写 `initConfigPanel()` 函数中 provider 恢复逻辑：根据已保存的 provider 值找到对应卡片并添加 `.selected` class + 展开配置面板 + 填充字段值
- [x] 4.6 移除旧的 `onProviderChange(selectEl, section)` 函数及其相关调用
- [x] 4.7 为所有 `.provider-card` 元素绑定 click 事件（在 `initConfigPanel` 或页面初始化时）

## 5. 响应式适配

- [x] 5.1 在 `styles.css` 中添加 `@media` 规则：当面板宽度不足时，卡片网格从 4 列降为 3 列或 2 列

## 6. 手动验证

- [x] 6.1 验证：选中各 Provider 卡片后配置面板正确填充 baseUrl/model，格式标签和获取 Key 链接正确
- [x] 6.2 验证：Ollama 隐藏 API Key、自定义显示 format radio、页面刷新后选中态恢复
- [x] 6.3 验证：保存配置后 WAF2 收到正确的 provider/format/baseUrl/model/apiKey
