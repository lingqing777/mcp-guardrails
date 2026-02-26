## MODIFIED Requirements

### Requirement: DASH-20 管理后台 Tab 页
管理后台 MUST 包含以下 Tab 页（含 LLM 配置变更）：

| Tab | 功能 |
|-----|------|
| 态势感知 | 攻击日志、拓扑图、威胁等级、OWASP 图表、WAF 对比（全屏可用） |
| 概览 | WAF1/WAF2 状态、拦截率、总量统计、Top 检测类别、最近检测 |
| MCP Servers | Server 列表+状态、添加/删除/编辑、工具列表、连接操作 |
| WAF1 | 全局开关、逐条规则开关（10 类）、趋势图、检测历史 |
| WAF2 | 全局开关、**LLM Provider 下拉/Base URL/Model/Key** 配置、请求/响应分析开关、缓存状态 |
| 检测记录 | 检测时间线、按类型/严重度/来源筛选 |
| 配置 | 目标应用 URL、**LLM Provider 下拉/Base URL/Model/API Key**、运行模式（full/lite）切换 |

WAF2 Tab 和 配置 Tab 中的 LLM 配置区域 MUST 包含以下 UI 元素（替代原 "API Key (Qwen DashScope)" 单输入框）：
1. **Provider 下拉选择**：预设 12 个厂商 + "自定义" 选项
2. **格式标签**：Provider 下拉下方显示当前 format 的彩色 badge（openai=蓝色、anthropic=橙色、gemini=绿色）
3. **获取 Key 链接**：显示当前 Provider 的 API Key 申请链接（无链接时隐藏）
4. **Base URL 输入框**：选择 Provider 后自动填充，可手动修改
5. **Model 输入框**：选择 Provider 后自动填充推荐模型，可手动修改
6. **API Key 输入框**：密码类型，Ollama 预设时整行隐藏并显示 "本地部署，无需 API Key" 提示
7. **格式选择器**：仅在选择 "自定义" 时显示，3 个 radio（OpenAI 兼容 / Anthropic / Gemini 原生）

#### Scenario: 选择预设 Provider 自动填充
- **WHEN** 用户在 Provider 下拉选择 "DeepSeek"
- **THEN** Base URL 输入框自动填充 `https://api.deepseek.com/v1`
- **AND** Model 输入框自动填充 `deepseek-chat`
- **AND** 格式标签显示蓝色 "OpenAI 兼容"
- **AND** 获取 Key 链接指向 DeepSeek 平台
- **AND** API Key 输入框清空，等待用户输入

#### Scenario: 选择 Anthropic Claude
- **WHEN** 用户在 Provider 下拉选择 "Anthropic Claude"
- **THEN** Base URL 输入框自动填充 `https://api.anthropic.com`
- **AND** Model 输入框自动填充 `claude-sonnet-4-5-20250929`
- **AND** 格式标签显示橙色 "Anthropic"
- **AND** 获取 Key 链接指向 Anthropic Console

#### Scenario: 选择 Google Gemini
- **WHEN** 用户在 Provider 下拉选择 "Google Gemini"
- **THEN** Base URL 输入框自动填充 `https://generativelanguage.googleapis.com`
- **AND** Model 输入框自动填充 `gemini-2.5-flash`
- **AND** 格式标签显示绿色 "Gemini 原生"
- **AND** 获取 Key 链接指向 Google AI Studio

#### Scenario: 选择 Ollama — API Key 隐藏
- **WHEN** 用户在 Provider 下拉选择 "Ollama (本地)"
- **THEN** API Key 输入行淡出隐藏
- **AND** 显示 "本地部署，无需 API Key" 提示文字
- **AND** 格式标签显示蓝色 "OpenAI 兼容"

#### Scenario: 选择自定义 Provider
- **WHEN** 用户在 Provider 下拉选择 "自定义"
- **THEN** Base URL 和 Model 输入框清空
- **AND** 格式选择器出现（3 个 radio：OpenAI 兼容 / Anthropic / Gemini 原生，默认选中 OpenAI 兼容）
- **AND** 用户可自由输入任意 Base URL 和 Model

#### Scenario: 手动修改自动填充值
- **WHEN** 用户选择 Provider 后手动修改了 Base URL 或 Model
- **THEN** 保留用户修改的值，不因后续操作覆盖

#### Scenario: 保存 LLM 配置
- **WHEN** 用户填写完 LLM 配置并点击保存
- **THEN** `provider`、`baseUrl`、`model`、`apiKey`、`format` 五个字段全部提交到 API
- **AND** 配置同步到 WAF2 容器

## ADDED Requirements

### Requirement: DASH-50 Provider 预设映射表
Dashboard 前端 MUST 内置 `LLM_PROVIDERS` 映射表，包含 12 个预设厂商和 1 个自定义选项。每个预设 MUST 包含 `label`（显示名称）、`format`（API 格式：openai/anthropic/gemini）、`baseUrl`（默认 Base URL）、`model`（推荐模型）、`keyUrl`（API Key 申请链接，可为空）。

#### Scenario: 映射表内容完整
- **WHEN** Dashboard 加载 LLM 配置面板
- **THEN** Provider 下拉菜单包含以下选项：通义千问 (DashScope)、OpenAI、DeepSeek、Anthropic Claude、Google Gemini、Moonshot (Kimi)、智谱 AI (GLM)、SiliconFlow、百度文心、豆包 (火山引擎)、Ollama (本地)、自定义

### Requirement: DASH-51 去除 Qwen 硬编码文案
Dashboard 中所有 "(Qwen DashScope)" 文案标注 MUST 移除，替换为通用的 LLM 配置 UI。包括但不限于：
- full 模式配置面板的 API Key 标签
- lite 模式配置面板的 API Key 标签
- WAF2 Tab 中的 LLM 配置区域

#### Scenario: 配置面板无 Qwen 特定文案
- **WHEN** 用户打开配置 Tab 或 WAF2 Tab
- **THEN** 界面中不出现 "Qwen"、"DashScope"、"千问" 等厂商特定文案
- **AND** 仅在 Provider 下拉选项中展示厂商名称

### Requirement: DASH-52 Ollama 无需 API Key 提示
当用户选择 Ollama Provider 时，Dashboard MUST 隐藏 API Key 输入行并显示提示。

#### Scenario: Ollama Provider 选中
- **WHEN** 用户在 Provider 下拉选择 "Ollama (本地)"
- **THEN** API Key 输入行以 opacity + max-height 动画淡出隐藏
- **AND** 显示 "本地部署，无需 API Key" 占位提示

#### Scenario: 从 Ollama 切换到其他 Provider
- **WHEN** 用户从 "Ollama (本地)" 切换到其他 Provider
- **THEN** API Key 输入行以动画恢复显示
- **AND** 占位提示隐藏

### Requirement: DASH-53 格式标签样式
Dashboard MUST 为 3 种 API 格式提供视觉差异化的彩色标签。

#### Scenario: 格式标签颜色
- **WHEN** Provider 的 format 为 `openai`
- **THEN** 格式标签显示蓝色（#58a6ff）文字 "OpenAI 兼容"
- **WHEN** Provider 的 format 为 `anthropic`
- **THEN** 格式标签显示橙色（#f0883e）文字 "Anthropic"
- **WHEN** Provider 的 format 为 `gemini`
- **THEN** 格式标签显示绿色（#3fb950）文字 "Gemini 原生"

### Requirement: DASH-54 Provider 切换过渡动画
Dashboard 中 Provider 切换时涉及的动态元素 MUST 使用平滑过渡动画（`transition: all 0.3s ease`），包括 API Key 行显隐、格式选择器显隐。
