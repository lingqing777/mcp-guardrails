## MODIFIED Requirements

### Requirement: 设计语言（全局约束）

层级：Dashboard

DASH-9 补充：主题切换 MUST 有视觉过渡动画，不可瞬间跳变。

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
