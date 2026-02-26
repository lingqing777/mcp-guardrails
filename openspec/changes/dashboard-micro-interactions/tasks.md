## 1. 按钮按压与 hover 统一 (CSS)

- [x] 1.1 在 `styles.css` 中为 `.btn:active:not(:disabled)` 添加 `transform: scale(0.96); transition: transform 0.1s ease`
- [x] 1.2 在 `styles.css` 中为 `.btn-danger:hover:not(:disabled)` 添加 `box-shadow: 0 0 0 3px rgba(224, 82, 99, 0.15), 0 0 12px rgba(224, 82, 99, 0.1)`
- [x] 1.3 在 `styles.css` 中为 `.btn-success:hover:not(:disabled)` 添加 `box-shadow: 0 0 0 3px rgba(115, 191, 105, 0.15), 0 0 12px rgba(115, 191, 105, 0.1)`

## 2. Tab 滑动指示条

- [x] 2.1 在 `index.html` 的 `.tabs` 容器末尾添加 `<div class="tab-indicator"></div>` 元素
- [x] 2.2 在 `styles.css` 中添加 `.tab-indicator` 样式：绝对定位底部、高度 2px、accent 色、border-radius 1px、`transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1), width 0.3s cubic-bezier(0.4, 0, 0.2, 1)`
- [x] 2.3 在 `styles.css` 中将 `.tab.active` 的 `border-bottom-color: var(--accent)` 移除（由 indicator 替代）
- [x] 2.4 在 `app.js` 的 `initTabs()` 中添加 `updateTabIndicator()` 函数：读取 active tab 的 offsetLeft/offsetWidth，设置 indicator 的 transform/width
- [x] 2.5 在 `app.js` 的 tab click 事件中调用 `updateTabIndicator()`
- [x] 2.6 在 `app.js` 的 `initTabs()` 末尾调用 `updateTabIndicator()` 进行初始定位（无动画：先设 `transition:none`，设置位置后恢复 transition）

## 3. Toggle 弹性回弹 (CSS)

- [x] 3.1 在 `styles.css` 中将 `.toggle-switch::after` 的 `transition` 改为 `transform 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55)`
- [x] 3.2 在 `styles.css` 中同步将 `.toggle-sm::after` 的 `transition` 改为相同弹性缓动
- [x] 3.3 在 `styles.css` 中为 `.toggle-switch:hover` 添加 `box-shadow: 0 0 0 3px rgba(87, 148, 242, 0.12)` hover 发光
- [x] 3.4 在 `styles.css` 中为 `.toggle-switch.active:hover` 添加 `box-shadow: 0 0 0 3px var(--accent-glow)` accent 色发光

## 4. 输入框 hover/focus 增强 (CSS)

- [x] 4.1 在 `styles.css` 中为 `input[type="text"]:hover, input[type="password"]:hover, input[type="url"]:hover, select:hover` 添加 `border-color: var(--border-hover)` 过渡
- [x] 4.2 在 `styles.css` 中为 `input:focus, select:focus` 添加 `border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); outline: none` focus 态

## 5. 列表行 hover 提升 (CSS)

- [x] 5.1 在 `styles.css` 中为 `.detection-item:hover` 增加 `transform: translateY(-1px)` 和 `transition: transform 0.15s ease, background var(--transition)`
- [x] 5.2 在 `styles.css` 中为 `.waf-rule-row` 添加 `transition: background 0.15s ease; position: relative; padding-left: 8px`，为 `.waf-rule-row:hover` 添加 `background: var(--bg-surface-2)` 并通过 `::before` 伪元素显示左侧 2px accent 色条
- [x] 5.3 确认 `.server-card` 已有的 hover 效果过渡时序与 `var(--transition)` 一致

## 6. Modal 关闭动画

- [x] 6.1 在 `styles.css` 中添加 `.modal.modal-closing` 样式和 `@keyframes modal-bg-out`（opacity 1→0, 0.15s）
- [x] 6.2 在 `styles.css` 中添加 `.modal-closing .modal-content` 样式和 `@keyframes modal-slide-out`（scale 1→0.96, opacity 1→0, 0.15s）
- [x] 6.3 在 `app.js` 中修改 `closeServerModal()` 函数：先添加 `.modal-closing` class，监听 `animationend` 后再 `display:none` 并移除 class
- [x] 6.4 在 `app.js` 中修改 `openAddServerModal()` / `editCurrentServer()` 函数：打开时先移除 `.modal-closing` class（防止动画中重新打开的竞态）

## 7. 加载按钮状态

- [x] 7.1 在 `styles.css` 中添加 `.btn-loading` 样式：opacity 降低 + pointer-events:none + 内嵌 spinner（`::before` 旋转圆环）
- [x] 7.2 在 `styles.css` 中添加 `.btn-success-flash` 样式：背景变为 green 系 + checkmark 图标 + 1.5s 后过渡恢复
- [x] 7.3 在 `app.js` 的 `applyConfig()` 中：调用前给按钮添加 `.btn-loading` class + 修改文字为 "保存中..." + disabled
- [x] 7.4 在 `app.js` 的 `applyConfig()` 中：成功后移除 `.btn-loading`，添加 `.btn-success-flash` + 文字改为 "已保存"，setTimeout 1.5s 后恢复原始文字和 class

## 8. 验证与收尾

- [x] 8.1 验证所有按钮（primary/secondary/danger/success）的 :active 缩放和 hover 发光效果
- [x] 8.2 验证 Tab 指示条在 7 个 Tab 之间正确滑动，页面加载时初始定位正确
- [x] 8.3 验证 Toggle 开关弹性回弹效果和 hover 发光
- [x] 8.4 验证输入框 hover/focus 边框变化
- [x] 8.5 验证列表行 hover 提升和 accent 色条
- [x] 8.6 验证 Modal 关闭动画和快速重开场景
- [x] 8.7 验证"应用配置"按钮 loading→success→恢复三阶段
- [x] 8.8 验证 light 主题下所有微交互效果正常
