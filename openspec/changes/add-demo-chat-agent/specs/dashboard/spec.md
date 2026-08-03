## ADDED Requirements

### Requirement: Dashboard 提供演示 Tab
Dashboard MUST 新增「演示」Tab，展示 4 按钮矩阵（2 漏洞场景 × WAF 开/关）与流式聊天气泡区。影响层：Dashboard。

#### Scenario: 演示 Tab 渲染与按钮矩阵
- **WHEN** 登录用户切换到「演示」Tab
- **THEN** MUST 渲染按场景分组的 4 个按钮（每场景含「WAF 开」「WAF 关」）
- **AND** 按钮文案 MUST 标注场景名与 WAF 状态
- **AND** 场景列表 MUST 来源于 `GET /api/demo/scenarios`

#### Scenario: 点击按钮发起流式演示
- **WHEN** 用户点击某按钮
- **THEN** 前端 MUST 通过 `dashboard/services/api.js` 的 `demoChat(scenarioId, wafEnabled)` 以 SSE 连接 `POST /api/demo/chat`
- **AND** MUST 在聊天气泡区流式渲染 `user`/`token`/`tool_call`/`waf`/`tool_result` 事件
- **AND** WAF 拦截 MUST 以红色高亮+拦截图标呈现，放行以绿色呈现

#### Scenario: 视觉与动效一致性
- **WHEN** 演示 Tab 渲染或状态变化
- **THEN** MUST 复用现有 `styles.css` 设计系统（#0d1117 背景、Inter 字体、Linear 极光渐变点缀、Tabler 卡片布局）
- **AND** MUST 包含按钮 loading→streaming→done 过渡态与聊天气泡流式打字动效
- **AND** MUST NOT 引入与现有视觉冲突的设计语言

#### Scenario: 重试支持
- **WHEN** 单次演示结束（含 LLM 未触发预期工具的诚实兜底情形）
- **THEN** UI MUST 提供「重试」按钮以相同 `scenarioId`/`wafEnabled` 重新发起
