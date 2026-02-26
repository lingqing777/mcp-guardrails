## 1. HTML 结构改造 (index.html)

- [x] 1.1 为所有 6 个 `.config-section` 添加 `data-section-id` 属性：`mode` / `config-full` / `config-lite` / `guide` / `waf-rules` / `data-mgmt`
- [x] 1.2 为每个 `.config-section-header` 添加 `onclick="toggleConfigSection('xxx')"` 和 `<span class="config-section-chevron">▾</span>`
- [x] 1.3 为默认收起的 section（`guide` / `waf-rules` / `data-mgmt`）在 `.config-section` 上添加 `collapsed` class
- [x] 1.4 移除「配置指引」section 旧的 `accordion-content` 包装层和 `accordion-chevron` 元素，将内容直接放在 `.config-section-body` 内

## 2. CSS 样式 (styles.css)

- [x] 2.1 新增 `.config-section-header` 的 `cursor: pointer` 和 hover 背景色 `var(--bg-surface-2)` 过渡
- [x] 2.2 新增 `.config-section-chevron` 样式：右侧对齐、颜色 `var(--text-muted)`、`transition: transform 0.3s ease`
- [x] 2.3 新增 `.config-section.collapsed .config-section-body` 样式：`max-height: 0; opacity: 0; overflow: hidden; padding: 0 18px`
- [x] 2.4 为 `.config-section-body` 添加 `transition: max-height 0.35s ease, opacity 0.25s ease, padding 0.35s ease` 并设 `overflow: hidden`
- [x] 2.5 新增 `.config-section.collapsed .config-section-chevron` 旋转样式：`transform: rotate(-90deg)`

## 3. JS 交互逻辑 (app.js)

- [x] 3.1 新增 `toggleConfigSection(sectionId)` 函数：通过 `data-section-id` 选择器找到对应 `.config-section`，toggle `collapsed` class
- [x] 3.2 重构旧 `toggleAccordion()` 函数，移除 `config-guide` 硬编码分支，改为调用 `toggleConfigSection('guide')`
- [x] 3.3 在 `initConfigPanel()` 或页面初始化时确保默认收起的 section 带有 `collapsed` class
- [x] 3.4 将 `toggleConfigSection` 挂载到 `window` 上以供 HTML onclick 调用

## 4. 验证

- [x] 4.1 验证：5 个 section 的展开/收起动画流畅，chevron 旋转正确
- [x] 4.2 验证：默认展开/收起状态正确（防护模式+快速配置展开，其余收起）
- [x] 4.3 验证：收起状态下 section 内部表单不可见且不占空间
- [x] 4.4 验证：模式切换（full↔lite）后对应快速配置 section 显示正确且可收缩
