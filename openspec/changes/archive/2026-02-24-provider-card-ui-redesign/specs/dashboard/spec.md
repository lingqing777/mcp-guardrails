## MODIFIED Requirements

### Requirement: 管理后台

- DASH-20: 管理后台 MUST 包含 7 个 Tab 页，"态势感知"SHALL 位于最前面作为默认激活 Tab：

| Tab | 功能 |
|-----|------|
| 态势感知 | 实时攻击日志流、双层防护拓扑图、威胁等级仪表盘、OWASP 分类统计、WAF1/WAF2 拦截对比（详见 display-screen spec） |
| 概览 | WAF1/WAF2 状态、拦截率、总量统计、Top 检测类别、最近检测 |
| MCP Servers | Server 列表+状态、添加/删除/编辑、工具列表、连接操作 |
| WAF1 | 全局开关、逐条规则开关（10 类）、趋势图、检测历史 |
| WAF2 | 全局开关、**LLM Provider 卡片网格选择器**配置、请求/响应分析开关、缓存状态 |
| 检测记录 | 检测时间线、按类型/严重度/来源筛选 |
| 配置 | 目标应用 URL、**LLM Provider 卡片网格选择器**、运行模式（full/lite）切换 |

  WAF2 Tab 和 配置 Tab 中的 LLM 配置区域 MUST 使用以下 UI 结构（替代原 `<select>` 下拉框）：

  1. **Provider 卡片网格**：4 列 CSS Grid 布局，展示 18 个预设 + 1 个"自定义"卡片
  2. **卡片顶部色条**：每张卡片顶部 3px border-top 标识 API format 类型（蓝色 #58a6ff = openai / 橙色 #f0883e = anthropic / 绿色 #3fb950 = gemini）
  3. **卡片内容**：Provider 名称（主标题）+ format 类型文字（副标题）
  4. **卡片交互**：hover 时边框变亮 + 微微上浮（translateY -1px）；选中时边框变为 format 色 + box-shadow 外发光 + 背景微亮
  5. **配置面板滑出**：选中任意卡片后，卡片网格下方滑出配置面板（max-height + opacity transition），包含：
     - Base URL 输入框（自动填充，可编辑）
     - Model 输入框（自动填充，可编辑）
     - API Key 输入框（密码类型 + 显示/隐藏切换）
     - 获取 Key 链接（指向当前 Provider 的 API Key 申请页面）
     - 协议标签（只读，显示当前 format 名称）
  6. **Ollama 特殊处理**：选中 Ollama 时 API Key 行隐藏，显示"本地部署，无需 API Key"
  7. **自定义特殊处理**：选中"自定义"时额外显示 format 三选一 radio（OpenAI 兼容 / Anthropic / Gemini 原生）
  8. **Provider 预设**：MUST 包含以下 18 个预设（按排列顺序）：

  | 行 | Col 1 | Col 2 | Col 3 | Col 4 |
  |----|-------|-------|-------|-------|
  | 1 | 通义千问 (DashScope) | OpenAI | DeepSeek | Grok (xAI) |
  | 2 | Anthropic Claude | Google Gemini | Groq | Mistral |
  | 3 | Moonshot (Kimi) | 智谱 AI (GLM) | SiliconFlow | Perplexity |
  | 4 | 百度文心 | 豆包 (火山引擎) | 讯飞星火 | 腾讯混元 |
  | 5 | Ollama (本地) | 自定义 | — | — |

  #### Scenario: 卡片网格展示 19 个选项
  - **WHEN** 用户打开配置 Tab 或 WAF2 Tab 的 LLM 配置区域
  - **THEN** 显示 4 列 × 5 行的卡片网格
  - **AND** 每张卡片顶部有 3px 色条标识 format（蓝/橙/绿）
  - **AND** 当前已选 Provider 的卡片处于选中态（边框发光）

  #### Scenario: 选中卡片后滑出配置面板
  - **WHEN** 用户点击 "DeepSeek" 卡片
  - **THEN** 该卡片进入选中态（边框发光 + 背景微亮）
  - **AND** 卡片网格下方滑出配置面板（0.3s transition）
  - **AND** Base URL 自动填充 `https://api.deepseek.com/v1`
  - **AND** Model 自动填充 `deepseek-chat`
  - **AND** 显示 "获取 Key →" 链接指向 DeepSeek 平台
  - **AND** 协议标签显示 "OpenAI 兼容"

  #### Scenario: 选中 Anthropic Claude 卡片
  - **WHEN** 用户点击 "Anthropic Claude" 卡片
  - **THEN** 卡片顶部色条为橙色，选中态边框为橙色发光
  - **AND** 配置面板 Base URL 填充 `https://api.anthropic.com`
  - **AND** Model 填充 `claude-sonnet-4-5-20250929`
  - **AND** 协议标签显示 "Anthropic"

  #### Scenario: 选中 Google Gemini 卡片
  - **WHEN** 用户点击 "Google Gemini" 卡片
  - **THEN** 卡片顶部色条为绿色，选中态边框为绿色发光
  - **AND** 配置面板 Base URL 填充 `https://generativelanguage.googleapis.com`
  - **AND** Model 填充 `gemini-2.5-flash`
  - **AND** 协议标签显示 "Gemini 原生"

  #### Scenario: 选中 Ollama — API Key 隐藏
  - **WHEN** 用户点击 "Ollama (本地)" 卡片
  - **THEN** 配置面板中 API Key 输入行淡出隐藏
  - **AND** 显示 "本地部署，无需 API Key" 提示文字
  - **AND** Base URL 填充 `http://localhost:11434/v1`

  #### Scenario: 选中自定义 — 显示 format 选择器
  - **WHEN** 用户点击 "自定义" 卡片
  - **THEN** 配置面板额外显示 3 个 format radio 按钮
  - **AND** Base URL 和 Model 输入框为空，等待用户手动输入

  #### Scenario: 卡片 hover 效果
  - **WHEN** 用户鼠标悬停在未选中的卡片上
  - **THEN** 卡片边框变亮（border-color 变为 --border-hover）
  - **AND** 卡片微微上浮（translateY(-1px)）

  #### Scenario: 页面加载恢复选中态
  - **WHEN** 页面加载且已保存 provider 配置为 "anthropic"
  - **THEN** "Anthropic Claude" 卡片处于选中态
  - **AND** 配置面板已展开并显示对应配置值
  - **AND** 自定义 provider 时 format radio 恢复为已保存的 format 值

  #### Scenario: 新增 Provider — Grok (xAI)
  - **WHEN** 用户点击 "Grok (xAI)" 卡片
  - **THEN** Base URL 填充 `https://api.x.ai/v1`
  - **AND** Model 填充 `grok-2`
  - **AND** 获取 Key 链接指向 `https://console.x.ai/`

  #### Scenario: 新增 Provider — Groq
  - **WHEN** 用户点击 "Groq" 卡片
  - **THEN** Base URL 填充 `https://api.groq.com/openai/v1`
  - **AND** Model 填充 `llama-3.3-70b-versatile`

  #### Scenario: 新增 Provider — Mistral
  - **WHEN** 用户点击 "Mistral" 卡片
  - **THEN** Base URL 填充 `https://api.mistral.ai/v1`
  - **AND** Model 填充 `mistral-large-latest`

  #### Scenario: 新增 Provider — Perplexity
  - **WHEN** 用户点击 "Perplexity" 卡片
  - **THEN** Base URL 填充 `https://api.perplexity.ai`
  - **AND** Model 填充 `sonar`

  #### Scenario: 新增 Provider — 讯飞星火
  - **WHEN** 用户点击 "讯飞星火" 卡片
  - **THEN** Base URL 填充 `https://spark-api-open.xf-yun.com/v1`
  - **AND** Model 填充 `generalv3.5`

  #### Scenario: 新增 Provider — 腾讯混元
  - **WHEN** 用户点击 "腾讯混元" 卡片
  - **THEN** Base URL 填充 `https://api.hunyuan.cloud.tencent.com/v1`
  - **AND** Model 填充 `hunyuan-lite`
