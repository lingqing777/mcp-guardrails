## Context

配置 Tab 有 5 个 `.config-section`：防护模式、快速配置（full/lite 切二选一）、配置指引、WAF 规则开关、数据管理。目前只有「配置指引」做了手风琴收起（通过 `toggleAccordion('config-guide')` 硬编码实现），其余 4 个 section 始终展开。

现有手风琴机制：`config-guide` 用 JS 直接操作 `content.style.maxHeight`，chevron 用 `style.transform` 旋转。另有一套 `.accordion-item.expanded` 的 CSS class 机制（态势感知等面板在用），两套机制并存。

## Goals / Non-Goals

**Goals:**
- 所有 5 个 config-section 均可点击 header 收缩/展开
- 统一使用 CSS class 驱动动画（`.config-section.collapsed`），废弃 inline style 操控
- 防护模式、快速配置默认展开；配置指引、WAF 规则、数据管理默认收起
- header hover 有视觉反馈
- 展开/收起过渡流畅（max-height + opacity transition）

**Non-Goals:**
- 不改变 section 内容或功能逻辑
- 不引入 JS 框架或第三方手风琴库
- 不修改非配置 Tab 的其他页面

## Decisions

### D1: 用 `.collapsed` class 而非 `.expanded`

**决策**: 给 `.config-section` 添加 `.collapsed` class 表示收起态，无 class 即展开。

**理由**: 配置页大部分 section 默认展开，用 `.collapsed` 只需在少数收起的元素上加 class，HTML 更干净。收起态下 `.config-section-body` 设 `max-height: 0; opacity: 0; overflow: hidden`。

**替代方案**: 用 `.expanded` class。需要在多数元素上加 class，HTML 更啰嗦。

### D2: 每个 section 用 data-section-id 属性标识

**决策**: 在 `.config-section` 上添加 `data-section-id="mode"` / `"config-full"` / `"config-lite"` / `"guide"` / `"waf-rules"` / `"data-mgmt"` 属性，`toggleConfigSection(id)` 通过 `querySelector` 定位。

**理由**: 比硬编码 DOM id 更语义化，且不会与现有 `id="config-full"` 等冲突。

### D3: chevron 放在 `.config-section-header` 右侧

**决策**: 在每个 `.config-section-header` 内追加 `<span class="config-section-chevron">▾</span>`，收起时 CSS rotate(−90deg)，展开时 rotate(0)。

**理由**: 与现有「配置指引」的 chevron 位置一致。`▾`（U+25BE）比 `▼` 更小巧精致。

### D4: header hover 反馈

**决策**: `.config-section-header` 添加 `cursor: pointer` 和 hover 背景色 `var(--bg-surface-2)`。

**理由**: 不加 hover 反馈用户不知道能点。

### D5: 快速配置 section 联动

**决策**: `config-full` 和 `config-lite` 两个 section 跟随模式切换的显隐逻辑保持不变（`selectMode()` 控制 `display: none/block`），手风琴只控制当前可见 section 的收缩。

**理由**: 两套逻辑正交，不会冲突。

## Risks / Trade-offs

- **max-height 动画需设固定上限** → 使用 `max-height: 800px` 足够覆盖所有 section 内容，过渡时间 0.35s 体感流畅
- **收起时内部表单输入焦点** → `overflow: hidden` 会裁剪，但 config section 收起时用户不会操作表单，无实际影响
- **「配置指引」已有 `.accordion-content` 包装** → 重构时需移除旧的 `accordion-content` 包装，统一用 `.config-section-body` 的 collapse 控制
