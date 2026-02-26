## Why

Dashboard 各交互元素（按钮、Tab、开关、输入框、列表行、弹窗）缺乏触觉反馈和动效，点击/切换时感觉"干巴巴"，与 Grafana + Linear 的高端设计语言不匹配。需要系统性地为所有交互元素补充微交互动效，提升操作反馈感和产品质感。

## What Changes

**P0 — 按钮按压与 hover 统一**
- 所有 `<button>` 和可点击操作元素增加 `:active` 缩放（scale 0.96）按压反馈
- 统一 hover 态：边框变亮 + 微弱 box-shadow 外发光

**P1 — Tab / Toggle / Input 交互增强**
- Tab 切换增加滑动指示条（底部 2px accent bar，JS 驱动位置+宽度跟随当前 tab 滑动）
- Toggle 开关增加 hover 外发光 + 切换时弹性回弹（cubic-bezier overshoot）
- 输入框 hover 时边框过渡变亮，focus 时 accent 色边框 + 微弱外发光

**P2 — 列表行 hover 提升 + 弹窗关闭动画**
- WAF 规则行、MCP Server 列表项、检测记录条目 hover 时 translateY(-1px) + 左侧 accent 色条显现
- Modal 关闭增加 scale + opacity 退出动画（不仅有进入动画）

**P3 — 加载按钮状态**
- "应用配置"按钮点击后显示 spinner 旋转动画 → 成功后变为 checkmark + 绿色闪烁 → 恢复原始状态

## Capabilities

### New Capabilities
- `micro-interactions`: 覆盖 Dashboard 全局的按钮/Tab/Toggle/Input/列表行/弹窗/加载按钮微交互动效体系

### Modified Capabilities
- `dashboard`: DASH-9 动效要求的细化补充 — 增加按钮按压、Tab 滑动指示条、Toggle 弹性、输入框 hover/focus、列表行 hover、弹窗关闭动画、加载按钮状态等具体微交互规格

## Impact

- **受影响文件**: `styles.css`（新增 CSS 动效规则）、`app.js`（Tab 指示条 JS 逻辑、加载按钮状态管理）、`index.html`（Tab 指示条 DOM 元素）
- **不影响**: WAF1/WAF2 后端逻辑、Docker 配置、路由注册顺序、API 接口
- **对 5 秒刷新的影响**: 加载按钮状态需确保刷新期间不干扰按钮动画；其余纯 CSS 动效无影响
- **无 Breaking Changes**
