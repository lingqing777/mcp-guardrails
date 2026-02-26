## Context

当前 `toggleTheme()` 只做 `setAttribute('data-theme', newTheme)` + emoji 文本替换。按钮是一个 `<span class="theme-icon">🌙</span>`，没有任何过渡效果。

参考：
- [View Transitions API circular reveal](https://akashhamirwasia.com/blog/full-page-theme-toggle-animation-with-view-transitions-api/) — 使用 `document.startViewTransition` + `clip-path: circle()` 从按钮位置展开新主题
- [Theme Toggles](https://toggles.dev/) — SVG sun/moon 图标通过 CSS transform 动画切换

## Goals / Non-Goals

**Goals:**
- 主题切换时有视觉连续性（圆形从按钮扩散），而非突然跳变
- 图标从 emoji 升级为 SVG，有旋转+缩放过渡
- 不支持 View Transitions API 的浏览器仍能正常切换（降级无动画）
- 尊重 `prefers-reduced-motion` 系统设置

**Non-Goals:**
- 不做 light theme 的完整颜色重新设计（已有 `[data-theme="light"]` 变量）
- 不引入第三方动画库

## Decisions

### D1: 圆形展开用 View Transitions API + clip-path

**决策**: 使用 `document.startViewTransition()` 捕获前后快照，然后在 `::view-transition-new(root)` 伪元素上用 Web Animations API 播放 `clip-path: circle(0px) → circle(maxRadius)` 动画。

**理由**: 这是 2024-2025 年最流行的主题切换动效方案。Chrome 111+、Edge 111+ 支持（裁判演示用的主流浏览器）。只需 ~20 行 JS + 4 行 CSS。

**替代方案**:
- 纯 CSS `transition` 所有颜色变量 → 太多属性需要 transition，性能差
- Canvas 截图 + 遮罩 → 实现复杂，效果不如 View Transitions 丝滑

### D2: SVG 双层叠放 + CSS 驱动状态切换

**决策**: 两个 SVG（sun、moon）绝对定位叠放在按钮内，通过 `[data-theme]` CSS 选择器控制 `opacity` + `transform`（rotate + scale）。

**理由**: 纯 CSS 驱动，不需要 JS 操作 DOM。图标切换自然跟随 View Transition 动画一起发生。

### D3: maxRadius 用 Math.hypot 计算

**决策**: 以按钮中心为圆心，取到四角的最大距离作为展开半径。`Math.hypot(Math.max(x, right), Math.max(y, bottom))`。

**理由**: 保证无论按钮在哪个位置，圆形都能覆盖整个视口。

## Risks / Trade-offs

- **Safari 不支持 View Transitions API** → 降级为无动画直接切换，功能不受影响。Safari 用户群体小，竞赛演示环境可控。
- **`::view-transition-*` 伪元素的 CSS 是全局的** → 只写了 `animation: none; mix-blend-mode: normal` 两条规则，不会影响其他 View Transition 用途。
