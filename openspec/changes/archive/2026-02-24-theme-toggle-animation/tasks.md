## 1. HTML 图标替换 (index.html)

- [x] 1.1 将 `.theme-toggle` 按钮内的 `<span class="theme-icon">🌙</span>` 替换为两个叠放的 SVG 元素：`.theme-icon-sun`（Feather icons sun）和 `.theme-icon-moon`（Feather icons moon path）
- [x] 1.2 SVG 尺寸 MUST 为 18x18，viewBox 0 0 24 24，stroke="currentColor"，stroke-width="2"

## 2. CSS 样式 (styles.css)

- [x] 2.1 新增 `::view-transition-old(root)` 和 `::view-transition-new(root)` 规则：`animation: none; mix-blend-mode: normal`
- [x] 2.2 调整 `.theme-toggle` 为 `position: relative; display: flex; align-items: center; justify-content: center; width: 34px; height: 34px; padding: 0`
- [x] 2.3 新增 `.theme-icon-svg` 样式：`position: absolute; transition: transform 0.5s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.3s ease`
- [x] 2.4 Dark 模式默认状态：sun `opacity: 0; transform: rotate(45deg) scale(0.5)`，moon `opacity: 1; transform: rotate(0) scale(1)`
- [x] 2.5 Light 模式状态 `[data-theme="light"]`：sun `opacity: 1; transform: rotate(0) scale(1)` + `.sun-rays` 额外 `rotate(45deg)`，moon `opacity: 0; transform: rotate(-45deg) scale(0.5)`
- [x] 2.6 新增 `.theme-toggle:active { transform: scale(0.9) }` 按压微交互

## 3. JS 交互逻辑 (app.js)

- [x] 3.1 重写 `toggleTheme()` 为 `async function`，使用 `document.startViewTransition()` 包裹主题属性切换
- [x] 3.2 在 `transition.ready` 后，以按钮中心为圆心，`Math.hypot` 计算 maxRadius，对 `::view-transition-new(root)` 播放 `clip-path: circle()` 动画（500ms, ease-in-out）
- [x] 3.3 添加降级分支：不支持 `startViewTransition` 或 `prefers-reduced-motion: reduce` 时直接切换
- [x] 3.4 简化 `updateThemeIcon()` 为空函数（SVG 状态由 CSS `[data-theme]` 自动控制）

## 4. 验证

- [x] 4.1 验证：Chrome/Edge 中点击切换按钮，圆形从按钮位置展开新主题
- [x] 4.2 验证：SVG sun/moon 图标有旋转+缩放过渡，太阳光线额外旋转
- [x] 4.3 验证：按钮按下有 scale(0.9) 按压感
- [x] 4.4 验证：localStorage 正确保存主题，刷新后图标状态正确
