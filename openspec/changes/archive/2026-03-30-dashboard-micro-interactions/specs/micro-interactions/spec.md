# Micro-Interactions — Dashboard 全局微交互动效

## Purpose

定义 Dashboard 所有可交互元素的微交互动效规格，覆盖按钮、Tab、Toggle、输入框、列表行、弹窗、加载状态。

层级：Dashboard（前端 CSS + JS）

## Requirements

### Requirement: 按钮按压反馈
所有 `.btn` 元素在被按下时 MUST 提供缩放按压反馈。

#### Scenario: 按钮 active 态缩放
- **WHEN** 用户按下任意非 disabled 的 `.btn` 按钮
- **THEN** 按钮 MUST 缩放至 0.96 倍（`transform: scale(0.96)`）
- **AND** 释放后 MUST 恢复原始尺寸
- **AND** 过渡时间 MUST 为 0.1s ease

#### Scenario: disabled 按钮无反馈
- **WHEN** 用户按下 disabled 的按钮
- **THEN** 不产生缩放效果

### Requirement: 按钮 hover 统一发光
所有按钮变体在 hover 时 MUST 有一致的视觉反馈。

#### Scenario: secondary 按钮 hover
- **WHEN** 用户 hover `.btn-secondary`
- **THEN** 边框变亮至 `var(--border-hover)` + 背景变为 `var(--bg-surface-3)`

#### Scenario: danger 按钮 hover 发光
- **WHEN** 用户 hover `.btn-danger`
- **THEN** MUST 增加与 danger 色匹配的微弱 `box-shadow` 外发光

#### Scenario: success 按钮 hover 发光
- **WHEN** 用户 hover `.btn-success`
- **THEN** MUST 增加与 success 色匹配的微弱 `box-shadow` 外发光

### Requirement: Tab 滑动指示条
Tab 导航栏 MUST 有一个可滑动的 accent 色指示条跟随当前激活 tab。

#### Scenario: Tab 切换时指示条滑动
- **WHEN** 用户点击一个非激活的 Tab
- **THEN** 底部指示条 MUST 从当前 Tab 位置平滑滑动至新 Tab 位置
- **AND** 指示条宽度 MUST 等于目标 Tab 的文字宽度
- **AND** 滑动过渡时间 MUST 为 0.3s，缓动 `cubic-bezier(0.4, 0, 0.2, 1)`

#### Scenario: 页面加载时指示条初始化
- **WHEN** Dashboard 页面加载完成
- **THEN** 指示条 MUST 定位到默认激活 Tab（态势感知）下方
- **AND** 初始定位无动画（直接就位）

#### Scenario: 指示条颜色
- **WHEN** 指示条可见
- **THEN** 颜色 MUST 为 `var(--accent)`（#5794f2）
- **AND** 高度 MUST 为 2px
- **AND** 圆角 MUST 为 1px

### Requirement: Toggle 开关弹性回弹
Toggle 开关的圆点滑动 MUST 带有弹性过冲效果。

#### Scenario: Toggle 切换弹性动画
- **WHEN** 用户点击 Toggle 开关切换状态
- **THEN** 圆点滑动 MUST 使用 `cubic-bezier(0.68, -0.55, 0.265, 1.55)` 缓动
- **AND** 圆点会略微过冲目标位置后回弹到正确位置

#### Scenario: Toggle hover 外发光
- **WHEN** 用户 hover Toggle 开关
- **THEN** 开关 MUST 显示微弱的 `box-shadow` 外发光
- **AND** 光晕颜色跟随当前状态（active 态用 accent 色，inactive 态用 neutral 色）

### Requirement: 输入框 hover 和 focus 增强
所有文本输入框和 select 在 hover/focus 时 MUST 有边框过渡反馈。

#### Scenario: 输入框 hover 边框变亮
- **WHEN** 用户 hover 一个未 focus 的输入框
- **THEN** 边框颜色 MUST 过渡至 `var(--border-hover)`

#### Scenario: 输入框 focus 态
- **WHEN** 输入框获得焦点
- **THEN** 边框颜色 MUST 变为 `var(--accent)`
- **AND** MUST 显示 accent 色微弱外发光（`box-shadow: 0 0 0 3px var(--accent-glow)`）
- **AND** 过渡时间 MUST 为 0.2s

### Requirement: 列表行 hover 提升
WAF 规则行、检测记录条目 hover 时 MUST 有提升感。

#### Scenario: 检测记录 hover 提升
- **WHEN** 用户 hover `.detection-item`
- **THEN** MUST 增加 `translateY(-1px)` 上浮
- **AND** 背景变为 `var(--bg-surface-3)`

#### Scenario: WAF 规则行 hover 指示
- **WHEN** 用户 hover `.waf-rule-row`
- **THEN** MUST 显示左侧 2px accent 色条
- **AND** 背景微变（`var(--bg-surface-2)` 提亮）

#### Scenario: Server 卡片 hover 一致性
- **WHEN** 用户 hover `.server-card`
- **THEN** hover 效果 MUST 与现有一致（边框变亮 + box-shadow）
- **AND** 过渡时序 MUST 统一为 `var(--transition)`

### Requirement: Modal 关闭动画
Modal 关闭时 MUST 有退出过渡动画，而非瞬间消失。

#### Scenario: Modal 关闭退出动画
- **WHEN** 用户关闭 Modal（点击关闭按钮或背景遮罩）
- **THEN** Modal 内容 MUST 以 `scale(0.96) + opacity(0)` 动画退出
- **AND** 背景遮罩 MUST 以 `opacity(0)` 淡出
- **AND** 动画时长 MUST 为 0.15s
- **AND** 动画完成后 Modal 才从视觉上移除

#### Scenario: Modal 关闭后立即重新打开
- **WHEN** Modal 退出动画尚未结束时用户再次触发打开
- **THEN** MUST 中断退出动画，立即以进入动画打开

### Requirement: 加载按钮状态
"应用配置"按钮 MUST 在提交过程中显示加载状态反馈。

#### Scenario: 点击后进入 loading 态
- **WHEN** 用户点击"应用配置"按钮
- **THEN** 按钮 MUST 进入 loading 态：文字变为 "保存中..."，左侧显示 spinner 旋转动画
- **AND** 按钮 MUST 变为 disabled 防止重复点击
- **AND** 按钮宽度 MUST 保持不变（`min-width` 锁定）

#### Scenario: 保存成功后进入 success 态
- **WHEN** 配置保存 API 返回成功
- **THEN** 按钮 MUST 过渡为 success 态：文字变为 "已保存"，左侧 spinner 替换为 checkmark
- **AND** 按钮背景 MUST 短暂变为 `var(--color-green)` 系
- **AND** success 态 MUST 持续 1.5 秒后恢复原始状态

#### Scenario: 保存失败恢复
- **WHEN** 配置保存 API 返回失败
- **THEN** 按钮 MUST 立即恢复原始态
- **AND** 错误提示由现有逻辑处理（不在按钮上显示错误态）
