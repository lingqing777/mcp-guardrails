# Dashboard — 可视化仪表盘

## Purpose

为系统管理员提供安全事件可视化、配置管理和 MCP Server 管理的 Web 界面。
包含管理后台（日常操作）和展示大屏（答辩演示）两个维度。

层级：MCP Hub（前端静态资源 + API）

## Requirements

### 设计语言（全局约束）

- DASH-1: UI 风格 MUST 保持 Grafana 暗色系 + Linear 极光渐变 + Tabler 布局的统一调性
- DASH-2: 主背景色 MUST 为纯黑 (#0d1117)，拒绝花哨的蓝紫渐变
- DASH-3: 配色 MUST 参考 Grafana SIEM Dashboard (https://grafana.com/grafana/dashboards/21565-siem-xdr-wazuh-4-8-0/)
- DASH-4: 渐变效果 MUST 参考 Linear.app (https://linear.app) 的极光渐变风格
- DASH-5: 组件布局 MAY 参考 Tabler (https://preview.tabler.io/) 的现代仪表盘模式
- DASH-6: 字体 MUST 为 Inter，回退系统无衬线字体
- DASH-7: 所有 UI 变更 MUST 追求设计感和美术感，减少 AI 生成痕迹
- DASH-8: UI MUST 参考成熟产品的设计模式，不自创不成熟的交互
- DASH-9: UI MUST 有动态感和现代感，包括适当的过渡动画、状态变化动效。主题切换 MUST 有视觉过渡动画，不可瞬间跳变。

  #### Scenario: 圆形展开切换（支持 View Transitions 的浏览器）
  - **WHEN** 用户在支持 View Transitions API 的浏览器中点击主题切换按钮
  - **THEN** 新主题以按钮位置为圆心，通过 `clip-path: circle()` 向外展开覆盖整个视口
  - **AND** 动画时长 MUST 为 500ms，缓动 `ease-in-out`
  - **AND** 展开半径 MUST 动态计算以覆盖视口所有角落

  #### Scenario: 降级切换（不支持 View Transitions 的浏览器）
  - **WHEN** 用户在不支持 View Transitions API 的浏览器中点击主题切换按钮
  - **THEN** 主题直接切换，无动画
  - **AND** 功能不受影响

  #### Scenario: 尊重 prefers-reduced-motion
  - **WHEN** 用户系统设置了 `prefers-reduced-motion: reduce`
  - **THEN** 主题切换 MUST 跳过圆形展开动画，直接切换

  #### Scenario: SVG 图标动画
  - **WHEN** 主题从 dark 切换到 light
  - **THEN** 月亮图标以旋转+缩放淡出，太阳图标以旋转+缩放淡入
  - **AND** 太阳光线 MUST 额外旋转 45°

  #### Scenario: 按钮按压微交互
  - **WHEN** 用户按下主题切换按钮
  - **THEN** 按钮 MUST 缩放至 0.9 倍（`:active` 态）

  #### Scenario: 全局按钮按压反馈
  - **WHEN** 用户按下 Dashboard 中任意非 disabled 的 `.btn` 按钮
  - **THEN** 按钮 MUST 缩放至 0.96 倍并在释放后恢复

  #### Scenario: Tab 滑动指示条
  - **WHEN** 用户切换 Tab
  - **THEN** 底部 accent 色指示条 MUST 平滑滑动至目标 Tab 位置
  - **AND** 过渡时间 MUST 为 0.3s

  #### Scenario: Modal 退出动画
  - **WHEN** 用户关闭任意 Modal
  - **THEN** Modal 内容 MUST 以 scale + opacity 动画退出，而非瞬间消失

- DASH-10: 新增 UI 元素 MUST 与现有视觉风格保持一致，不引入冲突的设计语言

### 技术栈

- DASH-15: 前端 MUST 使用原生 JS + CSS，无框架（Vue/React 等）
- DASH-16: 图表 MUST 使用 Chart.js
- DASH-17: 登录/注册页 HTML MUST 内联在 auth.js 模板字符串中
- DASH-18: Dashboard 主体 MUST 由 index.html + app.js + styles.css + services/api.js + components/ 组成

### 管理后台

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

- DASH-21: 数据 MUST 每 5 秒自动刷新
- DASH-22: 图表 MUST 包含：请求趋势图（时序）+ 检测类别分布图（饼图/柱状图）
- DASH-23: 配置 Tab 内所有 `.config-section` 区块 MUST 支持手风琴收缩/展开交互。每个 section header 可点击切换内容区域的可见性。

  各 section 默认状态 MUST 为：

  | Section | data-section-id | 默认状态 |
  |---------|-----------------|----------|
  | 防护模式 | `mode` | 展开 |
  | 快速配置 - 完整防护 | `config-full` | 展开 |
  | 快速配置 - 轻量防护 | `config-lite` | 展开 |
  | 配置指引 | `guide` | 收起 |
  | WAF 规则开关 | `waf-rules` | 收起 |
  | 数据管理 | `data-mgmt` | 收起 |

  #### Scenario: 点击收起展开的 section
  - **WHEN** 用户点击已展开 section 的 header
  - **THEN** 该 section 的 `.config-section-body` 以 `max-height` + `opacity` 过渡动画收起至不可见
  - **AND** header 右侧 chevron 旋转至 −90°

  #### Scenario: 点击展开收起的 section
  - **WHEN** 用户点击已收起 section 的 header
  - **THEN** 该 section 的 `.config-section-body` 以过渡动画展开
  - **AND** header 右侧 chevron 旋转回 0°

  #### Scenario: header hover 反馈
  - **WHEN** 用户鼠标悬停在 section header 上
  - **THEN** header 背景色变为 `var(--bg-surface-2)`
  - **AND** cursor 显示为 pointer

  #### Scenario: 页面加载默认状态
  - **WHEN** 配置 Tab 首次渲染
  - **THEN** 防护模式和当前模式对应的快速配置 section 默认展开
  - **AND** 配置指引、WAF 规则开关、数据管理 section 默认收起

  #### Scenario: 配置指引统一机制
  - **WHEN** 配置指引 section 使用新的统一手风琴机制
  - **THEN** 旧的 `toggleAccordion('config-guide')` 硬编码逻辑 MUST 被移除
  - **AND** 行为与其他 section 一致（class 驱动，非 inline style）

### MCP Server 管理

- DASH-25: Dashboard MUST 展示每个 Server 的独立状态指示（连接中/在线/离线/错误）
- DASH-26: Server 错误状态 MUST 显示具体错误信息，不能只显示"离线"
- DASH-27: 添加 Server 时校验失败 MUST 有即时的用户反馈
- DASH-28: 多 Server 操作（批量连接/断开）MUST 有逐条结果反馈

### 态势感知面板数据层

- DASH-29: 态势感知全屏面板（Monitor）的 `monitorRefresh()` MUST 每 2.5 秒从 3 个 API 拉取数据并分发给 5 个子渲染函数：
  - `/api/waf1/dashboard` → `w1Dashboard`
  - `${WAF2_BASE}/waf2/dashboard` → `w2Dashboard`
  - `/api/servers` → `serversData`
- DASH-29.1: `/api/waf1/history` 请求 MUST 被移除，不得作为 Monitor 的攻击日志数据源
- DASH-29.2: `monitorUpdateLogStream`、`monitorUpdateThreatLevel`、`monitorUpdateOwaspChart` MUST 接收 `w1Dashboard` 而不是 `w1History`

  #### Scenario: monitorRefresh 发起 3 个并行请求
  - **WHEN** 态势感知面板处于全屏状态且定时器触发刷新
  - **THEN** `monitorRefresh()` SHALL 发起 3 个 `fetch` 请求（waf1/dashboard, waf2/dashboard, servers）
  - **AND** SHALL NOT 请求 `/api/waf1/history`

  #### Scenario: w1Dashboard 传入所有子函数
  - **WHEN** 3 个 API 响应返回
  - **THEN** `w1Dashboard` SHALL 作为第一参数传入 `monitorUpdateLogStream`、`monitorUpdateThreatLevel`、`monitorUpdateOwaspChart`
  - **AND** `monitorUpdateLogStream` 不再接收 `w1History` 参数

### 攻击日志流 Log Stream 数据源

- DASH-29.3: `monitorUpdateLogStream(w1Dashboard, w2Dashboard)` MUST 从 `w1Dashboard.recentDetections[]` 和 `w2Dashboard.recent_detections[]` 提取攻击检测记录
- DASH-29.4: 双层记录 MUST 合并后按 timestamp 降序排列，最多显示 50 条

  #### Scenario: WAF1 检测事件出现在日志流中
  - **WHEN** WAF1 已拦截攻击且 `w1Dashboard.recentDetections` 包含记录
  - **THEN** 日志流 SHALL 显示每条 WAF1 记录，source 标记为 "WAF1"
  - **AND** category 取自 `detection.category`，severity 取自 `detection.severity`，reason 取自 `detection.reason`

  #### Scenario: WAF2 检测事件出现在日志流中
  - **WHEN** WAF2 已拦截攻击且 `w2Dashboard.recent_detections` 包含记录
  - **THEN** 日志流 SHALL 显示每条 WAF2 记录，source 标记为 "WAF2"

  #### Scenario: 双层记录按时间混合排序
  - **WHEN** WAF1 和 WAF2 都有检测记录
  - **THEN** 所有记录 SHALL 合并为一个列表并按 timestamp 降序排列
  - **AND** 日志流显示最多 50 条记录

  #### Scenario: 无检测记录时显示空态
  - **WHEN** WAF1 和 WAF2 均无检测记录
  - **THEN** 日志流 SHALL 显示 "暂无攻击记录" 空态占位

### 威胁等级面板 Threat Level 数据路径

- DASH-29.5: `monitorUpdateThreatLevel(w1Dashboard, w2Dashboard)` MUST 从 `w1Dashboard.last24h.bySeverity` 和 `w2Dashboard.by_severity` 读取 severity 分布
- DASH-29.6: critical / high / medium / low 四个等级的计数 MUST 聚合双层数据

  #### Scenario: WAF1 severity 计数被正确读取
  - **WHEN** WAF1 dashboard 返回 `{ last24h: { bySeverity: { high: 3, medium: 5 } } }`
  - **THEN** 威胁等级面板 high 计数 SHALL 包含 WAF1 的 3 条
  - **AND** medium 计数 SHALL 包含 WAF1 的 5 条

  #### Scenario: 双层 severity 聚合
  - **WHEN** WAF1 bySeverity 为 `{ high: 3 }` 且 WAF2 by_severity 为 `{ high: 2, critical: 1 }`
  - **THEN** 面板显示 critical=1, high=5, medium=0, low=0

  #### Scenario: WAF1 数据不可用时降级
  - **WHEN** WAF1 dashboard API 返回 null
  - **THEN** 威胁等级面板 SHALL 仅显示 WAF2 数据，不报错

### OWASP 攻击分类图表数据构建

- DASH-29.7: `monitorUpdateOwaspChart(w1Dashboard, w2Dashboard)` MUST 从 WAF1 `last24h.byCategory` 与 WAF2 `by_category` 构建 OWASP 聚合数据
- DASH-29.8: 前端 MUST 维护 WAF1 / WAF2 category → OWASP 映射，并将相同 OWASP 编号的计数累加

  #### Scenario: WAF1 分类映射为 OWASP
  - **WHEN** WAF1 byCategory 为 `{ sqlInjection: 3, pathTraversal: 2 }`
  - **THEN** OWASP 图表 SHALL 显示 A03:2021=3, A01:2021=2

  #### Scenario: 双层数据聚合到同一 OWASP 编号
  - **WHEN** WAF1 byCategory 含 `sqlInjection: 3` 且 WAF2 by_category 含 `sql_injection: 2`
  - **THEN** OWASP 图表中 A03:2021 SHALL 为 5（3+2）

  #### Scenario: WAF2 prompt_injection 映射为 LLM01
  - **WHEN** WAF2 by_category 含 `prompt_injection: 4`
  - **THEN** OWASP 图表 SHALL 包含 LLM01=4

  #### Scenario: 双层数据均为空时显示占位
  - **WHEN** WAF1 和 WAF2 的分类数据均为空或 null
  - **THEN** OWASP 图表 SHALL 显示 "暂无数据" 占位

### WAF 规则管理

- DASH-30: WAF1 的 10 类规则 MUST 各有独立的启用/禁用开关
- DASH-31: 规则名称映射：Dashboard 前端 `commandInjection` = WAF1 内部 `shellInjection`
- DASH-32: WAF2 的请求分析和响应分析 MUST 各有独立开关

### 路由与认证

- DASH-35: Dashboard 静态资源路由 MUST 在认证中间件之后（需要登录才能访问）
- DASH-36: `GET /` 和 `/dashboard/*` MUST 需要有效 Session
- DASH-37: 未认证访问 Dashboard MUST 重定向到 /login

### LLM Provider 配置 UI

- DASH-50: Provider 预设映射表 — Dashboard 前端 MUST 内置 `LLM_PROVIDERS` 映射表，包含 12 个预设厂商和 1 个自定义选项。每个预设 MUST 包含 `label`（显示名称）、`format`（API 格式：openai/anthropic/gemini）、`baseUrl`（默认 Base URL）、`model`（推荐模型）、`keyUrl`（API Key 申请链接，可为空）。

  #### Scenario: 映射表内容完整
  - **WHEN** Dashboard 加载 LLM 配置面板
  - **THEN** Provider 下拉菜单包含以下选项：通义千问 (DashScope)、OpenAI、DeepSeek、Anthropic Claude、Google Gemini、Moonshot (Kimi)、智谱 AI (GLM)、SiliconFlow、百度文心、豆包 (火山引擎)、Ollama (本地)、自定义

- DASH-51: 去除 Qwen 硬编码文案 — Dashboard 中所有 "(Qwen DashScope)" 文案标注 MUST 移除，替换为通用的 LLM 配置 UI。包括但不限于：
  - full 模式配置面板的 API Key 标签
  - lite 模式配置面板的 API Key 标签
  - WAF2 Tab 中的 LLM 配置区域

  #### Scenario: 配置面板无 Qwen 特定文案
  - **WHEN** 用户打开配置 Tab 或 WAF2 Tab
  - **THEN** 界面中不出现 "Qwen"、"DashScope"、"千问" 等厂商特定文案
  - **AND** 仅在 Provider 下拉选项中展示厂商名称

- DASH-52: Ollama 无需 API Key 提示 — 当用户选择 Ollama Provider 时，Dashboard MUST 隐藏 API Key 输入行并显示提示。

  #### Scenario: Ollama Provider 选中
  - **WHEN** 用户在 Provider 下拉选择 "Ollama (本地)"
  - **THEN** API Key 输入行以 opacity + max-height 动画淡出隐藏
  - **AND** 显示 "本地部署，无需 API Key" 占位提示

  #### Scenario: 从 Ollama 切换到其他 Provider
  - **WHEN** 用户从 "Ollama (本地)" 切换到其他 Provider
  - **THEN** API Key 输入行以动画恢复显示
  - **AND** 占位提示隐藏

- DASH-53: 格式标签样式 — Dashboard MUST 为 3 种 API 格式提供视觉差异化的彩色标签。

  #### Scenario: 格式标签颜色
  - **WHEN** Provider 的 format 为 `openai`
  - **THEN** 格式标签显示蓝色（#58a6ff）文字 "OpenAI 兼容"
  - **WHEN** Provider 的 format 为 `anthropic`
  - **THEN** 格式标签显示橙色（#f0883e）文字 "Anthropic"
  - **WHEN** Provider 的 format 为 `gemini`
  - **THEN** 格式标签显示绿色（#3fb950）文字 "Gemini 原生"

- DASH-54: Provider 切换过渡动画 — Dashboard 中 Provider 切换时涉及的动态元素 MUST 使用平滑过渡动画（`transition: all 0.3s ease`），包括 API Key 行显隐、格式选择器显隐。

### LLM 健康与验证

- DASH-60: 保存 LLM 配置前连通性预检 — Dashboard 保存 LLM 配置时（`applyConfig()` 流程），MUST 在实际保存前调用 `/waf2/test-llm` 接口验证 API Key 可用性。

  #### Scenario: API Key 有效 — 正常保存
  - **WHEN** 用户点击保存，test-llm 返回成功
  - **THEN** 配置正常保存
  - **AND** 显示成功提示

  #### Scenario: API Key 无效 — 警告后允许强制保存
  - **WHEN** 用户点击保存，test-llm 返回失败或超时
  - **THEN** MUST 弹出警告对话框，内容包含错误信息
  - **AND** 对话框提供"仍然保存"和"取消"两个选项
  - **AND** 用户选择"仍然保存"时正常保存配置
  - **AND** 用户选择"取消"时留在编辑状态，不保存

  #### Scenario: Ollama Provider — 跳过预检
  - **WHEN** 用户选择的 Provider 为 Ollama 且 API Key 为空
  - **THEN** 跳过 test-llm 验证，直接保存

  #### Scenario: test-llm 网络不可达 — 视为验证失败
  - **WHEN** test-llm 接口本身不可达（WAF2 容器未启动）
  - **THEN** 按验证失败处理，弹出警告对话框

- DASH-61: 态势感知 LLM 健康告警 — 态势感知面板 MUST 展示 WAF2 LLM 健康状态。当 WAF2 stats 中 `llm_errors > 0` 时，MUST 在面板顶部显示醒目的警告 banner。

  #### Scenario: LLM 正常 — 无告警
  - **WHEN** WAF2 stats 中 `llm_errors` 为 0
  - **THEN** 态势感知面板不显示 LLM 告警 banner

  #### Scenario: LLM 异常 — 显示告警
  - **WHEN** WAF2 stats 中 `llm_errors > 0`
  - **THEN** 态势感知面板顶部 MUST 显示警告 banner
  - **AND** banner 文案 MUST 包含 "WAF2 LLM 检测不可用" 和 "请检查 API Key 配置"
  - **AND** banner 样式 MUST 使用警告色调（amber/yellow），与现有 Grafana 暗色主题一致

  #### Scenario: 告警随刷新更新
  - **WHEN** Dashboard 5 秒自动刷新获取到新的 stats 数据
  - **THEN** banner 显示状态 MUST 根据最新 `llm_errors` 值更新

## Scenarios

### 正常登录访问

```
Given 用户已通过 /login 登录，拥有有效 Session
When  访问 http://localhost:4000/
Then  显示 Dashboard "态势感知"Tab（默认激活）
And   态势感知面板可见，其他 Tab 面板隐藏
And   WAF1/WAF2 状态卡片展示实时数据
And   数据每 5 秒自动刷新
```

### 查看检测记录

```
Given 系统已拦截多次攻击
When  用户切换到"检测记录"Tab
Then  展示检测时间线，最新记录在上
And   每条记录显示：时间、类型、category、severity、详情
And   用户可按类型/严重度筛选
```

### WAF1 规则开关

```
Given 用户在 WAF1 Tab
When  关闭 "SQL 注入" 规则开关
Then  开关状态立即更新
And   WAF1 不再检测 SQL 注入类请求
And   其他规则不受影响
```

### MCP Server 错误展示

```
Given 某个 MCP Server 配置了错误的 command
When  用户查看 MCP Servers Tab
Then  该 Server 状态显示为红色"错误"
And   鼠标悬停或展开可看到具体错误信息（如 "ENOENT: command not found"）
And   其他 Server 正常显示绿色"在线"
```

### 未认证访问

```
Given 用户未登录
When  直接访问 http://localhost:4000/
Then  302 重定向到 /login 页面
```
