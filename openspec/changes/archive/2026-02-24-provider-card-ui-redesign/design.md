## Context

Dashboard 配置 Tab 和 WAF2 Tab 中的 LLM Provider 选择器当前使用原生 `<select>` 下拉框 + 表单字段。用户反馈视觉过于朴素、缺乏设计感。现需替换为卡片网格选择器，同时将 Provider 预设从 12 个扩展到 18 个。

当前实现：
- `LLM_PROVIDERS` 对象（app.js）包含 12 个 provider 预设
- `onProviderChange()` 监听 select change 事件，自动填充 baseUrl/model
- Full 和 Lite 模式各有独立的 HTML `<select>` + 配置字段
- CSS 已有 `.format-badge`、`.provider-meta`、`.format-selector` 等样式

设计约束：
- 纯前端改动，不涉及后端/WAF2/Docker
- 必须保持 Grafana + Linear 暗色设计语言一致性
- 现有 Dashboard 已有 `.mode-card`（大卡片选择）和 `.model-option`（小 tile 网格）两种卡片模式可参考

## Goals / Non-Goals

**Goals:**
- 将 Provider 选择从下拉框升级为视觉丰富的卡片网格
- 通过顶部色条、hover/选中动效传达 format 信息，减少认知负担
- 新增 6 个 Provider（Grok/Groq/Mistral/Perplexity/讯飞星火/腾讯混元）
- Full 和 Lite 模式复用同一套卡片 HTML 结构和 JS 逻辑

**Non-Goals:**
- 不改变后端 API 或 WAF2 格式处理逻辑
- 不引入前端框架（保持原生 JS + CSS）
- 不做 Provider logo/icon 图片资源（纯文字 + 色彩）
- 不改变配置保存/加载的数据结构

## Decisions

### D1: 卡片网格布局 — 4 列 CSS Grid

**选择**: `display: grid; grid-template-columns: repeat(4, 1fr)` 固定 4 列。

**理由**: 18 个 provider + 自定义 = 19 项，4 列排 5 行（最后一行 3 项），视觉均衡。3 列太宽每张卡太大，5 列太挤文字放不下。现有 `.mode-card` 用 2 列 grid，`.model-option` 用 `auto-fit`，4 列固定 grid 在设置面板宽度内最合适。

**备选**: `flex-wrap` 自动换行 — 宽度变化时列数不可控，排列可能不整齐，放弃。

### D2: Format 色条 — 卡片顶部 3px border-top

**选择**: 每张卡片顶部 3px 实色 border-top，颜色由 format 决定：
- `openai` → `#58a6ff`（蓝）
- `anthropic` → `#f0883e`（橙）
- `gemini` → `#3fb950`（绿）

**理由**: 3px 色条足够传达分类信息，不喧宾夺主。参考 Linear.app 项目卡片的顶部彩条设计。比整张卡片染色更克制，比小色点更醒目。

### D3: 选中态 — 边框发光 + 背景微亮

**选择**: 选中卡片 `border-color` 变为 format 对应色，加 `box-shadow` 外发光，背景色微微提亮。

**理由**: 与现有 `.mode-card.selected` 的 glow 效果一致（`box-shadow: 0 0 0 1px var(--accent), 0 0 20px rgba(...)`)。保持设计语言统一。

### D4: 配置面板 — 选中卡片下方滑出

**选择**: 卡片网格下方放置一个 `.provider-config-panel` 容器，选中任意卡片后以 CSS transition 滑出显示（`max-height` + `opacity` 动画），内含 API Key / Base URL / Model 输入字段。

**理由**: 比把配置字段固定显示更紧凑。用户先选 provider，再看到对应的配置。参考 Vercel Integrations 面板——选中后展开详情。

**动画**: `max-height: 0 → 300px`, `opacity: 0 → 1`, `transition: 0.3s ease`。

### D5: Full/Lite 复用 — section 参数区分

**选择**: HTML 中 Full 和 Lite 各有一个卡片网格容器（ID 带 `-lite` 后缀），JS 函数通过 `section` 参数（`'full'` / `'lite'`）区分操作哪套 DOM 元素。

**理由**: 沿用现有的 Full/Lite 双套 DOM + `section` 参数模式，改动最小。

### D6: Provider 排列顺序

**选择**: 按使用频率和地域分组排列（不加显式分组标题）：
```
行1: 通义千问 | OpenAI   | DeepSeek  | Grok
行2: Claude   | Gemini   | Groq      | Mistral
行3: Moonshot | 智谱 AI  | SiliconFlow | Perplexity
行4: 百度文心 | 豆包     | 讯飞星火  | 腾讯混元
行5: Ollama   | 自定义   |           |
```

**理由**: 第一行放最常用的国内外 provider，第二行放独立 format 的 + 国际推理平台，第三四行国内厂商，最后一行特殊类型。通过排列顺序实现隐性分组，不需要显式标题占空间。

## Risks / Trade-offs

- **[卡片数量较多]** → 19 张卡片在小屏幕上可能拥挤。缓解: 响应式 `@media` 在窄屏时切换为 3 列或 2 列。
- **[无 Provider logo]** → 纯文字卡片可能不够直观。缓解: 顶部色条 + 副标题（format 名称）增加识别度。未来可添加 SVG icon。
- **[Full/Lite 双套 DOM]** → HTML 体积增加。缓解: 卡片结构简单，每张约 3-4 行 HTML，19 张 ≈ 60-80 行，可接受。
