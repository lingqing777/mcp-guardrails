## Why

当前 LLM Provider 选择使用原生 `<select>` 下拉框，视觉上过于朴素、缺乏设计感，与 Dashboard 整体 Grafana + Linear 暗色设计语言不匹配。同时 Provider 列表需要从 12 个扩展到 18 个（新增 Grok、Groq、Mistral、Perplexity、讯飞星火、腾讯混元），下拉框无法承载这么多选项的视觉展示。

## What Changes

- 将 `<select>` 下拉框替换为 **卡片网格（card grid）** 选择器，4 列排列，每张卡片带顶部 3px 色条标识 API format（蓝=openai / 橙=anthropic / 绿=gemini）
- 新增 6 个 Provider 预设：Grok (xAI)、Groq、Mistral、Perplexity、讯飞星火、腾讯混元
- 卡片交互：hover 上浮 + 边框变亮、选中态边框发光 + 背景微亮
- 选中卡片后，下方滑出配置面板（API Key / Model / Base URL），替代当前的固定表单布局
- Full 模式和 Lite 模式共用同一套卡片 UI 组件
- 自定义 Provider 卡片选中后额外显示 format 三选一 radio
- Ollama 卡片选中后隐藏 API Key 输入行，显示"本地部署"提示

## Capabilities

### New Capabilities

_无新增独立能力_

### Modified Capabilities

- `dashboard`: Provider 选择从 `<select>` 改为卡片网格，新增 6 个 provider 预设，选中后滑出配置面板
- `config`: LLM_PROVIDERS 扩展到 18 个预设（新增 grok/groq/mistral/perplexity/xfyun/hunyuan）

## Impact

- **前端 HTML**: index.html 中 Full/Lite 两处 Provider `<select>` 替换为卡片网格容器
- **前端 CSS**: styles.css 新增 provider-card 系列样式（卡片、网格、色条、选中态、滑出面板），移除旧的 `<select>` 相关样式
- **前端 JS**: app.js 中 LLM_PROVIDERS 扩展到 18 项，`onProviderChange()` 重写为卡片点击逻辑，`applyConfig()` / `initConfigPanel()` 适配卡片选择器
- **WAF2 / Docker / config**: 无变化（纯前端 UI 重构，后端 format/provider 逻辑已在 multi-llm-provider 中完成）
- **不影响 5 秒刷新机制**（Provider 选择不在自动刷新范围内）
