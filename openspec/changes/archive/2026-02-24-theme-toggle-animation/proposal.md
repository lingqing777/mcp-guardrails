## Why

当前明暗主题切换只是瞬间切换 `data-theme` 属性，没有任何过渡动画，图标也只是 emoji 互换（🌙/☀️），视觉体验粗糙，与 Dashboard 整体追求的"高端大气上档次"定位不符。

## What Changes

- 使用 View Transitions API 实现从按钮位置向外圆形展开的全页主题切换动画
- 将 emoji 图标替换为 SVG Sun/Moon 图标，带旋转+缩放切换动画
- 按钮增加 `:active` 按压缩放微交互
- 不支持 View Transitions 的浏览器降级为无动画切换

## Capabilities

### New Capabilities

_(无新 capability，增强现有 Dashboard 主题切换体验)_

### Modified Capabilities

- `dashboard`: 主题切换交互从无动画升级为圆形展开动画 + SVG 图标动画

## Impact

- `mcp-hub/src/dashboard/app.js` — 重写 `toggleTheme()` 为 async，使用 `document.startViewTransition` + `clip-path` 动画
- `mcp-hub/src/dashboard/styles.css` — 新增 `::view-transition-old/new(root)` 规则、SVG 图标切换动画、按钮微交互
- `mcp-hub/src/dashboard/index.html` — 按钮内 emoji 替换为两个叠放的 SVG 元素（sun + moon）
- 不影响 WAF1/WAF2 架构
- 不影响 Docker 配置
- 不影响 5 秒刷新机制
- 不涉及新路由
