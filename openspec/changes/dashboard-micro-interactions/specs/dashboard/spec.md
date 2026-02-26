## MODIFIED Requirements

### Requirement: UI 动效规范
- DASH-9: UI MUST 有动态感和现代感，包括适当的过渡动画、状态变化动效。主题切换 MUST 有视觉过渡动画，不可瞬间跳变。所有可交互元素（按钮、Tab、Toggle、输入框、列表行、弹窗）MUST 具备一致的微交互动效反馈体系（详见 micro-interactions spec）。

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
