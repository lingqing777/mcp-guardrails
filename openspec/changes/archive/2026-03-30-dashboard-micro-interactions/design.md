## Context

Dashboard 当前已具备 Grafana 暗色调 + Linear 极光渐变的视觉基底，但交互元素的动效覆盖不完整：
- 按钮仅 `.btn-primary` 有 hover box-shadow，其他变体（secondary/danger/success）无统一的 hover 发光；所有按钮均无 `:active` 按压反馈
- Tab 切换使用 `border-bottom: 2px solid` 硬切，无滑动指示条
- Toggle 开关仅有背景色过渡，缺乏弹性动效和 hover 态
- 输入框无 hover/focus 增强
- 列表行（`.detection-item`、`.waf-rule-row`、`.server-card`）hover 仅变背景色，缺乏提升感
- Modal 有进入动画（scale 0.96 → 1），但关闭时直接 `display:none` 无退出过渡
- "应用配置"按钮点击后无加载状态反馈

技术栈限制：原生 JS + CSS，无框架，所有 JS 全局挂 window。

## Goals / Non-Goals

**Goals:**
- 为 Dashboard 所有可交互元素补充一致的微交互动效
- 保持 Grafana + Linear 的设计语言统一性
- 纯 CSS 能解决的用纯 CSS，需要运行时计算的用最少量 JS
- 不引入任何新依赖

**Non-Goals:**
- 不改变现有功能逻辑（按钮行为、Tab 路由、配置保存等不变）
- 不做数字计数滚动（与 5 秒刷新冲突）
- 不改变现有 DOM 结构（除 Tab 指示条需新增一个 `<div>`）
- 不涉及后端 / Docker / 路由注册

## Decisions

### D1: Tab 滑动指示条 — JS 计算位置 + CSS transition

**选择**: 在 `.tabs` 容器内新增 `<div class="tab-indicator">` 绝对定位元素，JS 在 tab 切换时计算当前 active tab 的 `offsetLeft` 和 `offsetWidth`，通过 `style.transform` + `style.width` 更新位置，CSS `transition` 负责平滑滑动。

**替代方案**:
- 纯 CSS `:target` / `:checked` 方案 — 不适用，因为现有 tab 通过 JS class 切换
- CSS `scroll-snap` — 不适用，tab 不是滚动容器

**理由**: JS 计算宽度+位置 + CSS transition 是 Linear/Vercel 等产品的标准做法，代码量最小（~15 行 JS）。

### D2: Toggle 弹性回弹 — CSS cubic-bezier overshoot

**选择**: 将 `.toggle-switch::after` 的 `transition-timing-function` 改为 `cubic-bezier(0.68, -0.55, 0.265, 1.55)`（back-out 缓动），实现圆点滑动时的"过冲+回弹"效果。

**替代方案**: JS + Web Animations API 手动驱动弹性 — 过于复杂

**理由**: 单行 CSS 变更，无 JS，效果与 iOS 原生开关一致。

### D3: Modal 关闭动画 — CSS class + animationend 事件

**选择**: 关闭 modal 时先添加 `.modal-closing` class（触发 scale 1 → 0.96 + opacity 1 → 0 动画），`animationend` 后再 `display:none`。

**替代方案**: `dialog` 元素 `::backdrop` — 现有 modal 是 div 实现，迁移成本大

**理由**: 最小改动，仅需 ~8 行 JS + 1 个 keyframe。

### D4: 加载按钮状态 — 三阶段状态机

**选择**: "应用配置"按钮点击后进入 loading 态（文字替换为 spinner + "保存中..."），成功后进入 success 态（变为 checkmark + "已保存"，绿色闪烁 1.5s），然后恢复原始态。

**替代方案**: Toast 通知 — 已有类似机制但不够直观

**理由**: 按钮内嵌状态是 Vercel/Linear 的标准模式，用户注意力自然在按钮上。

### D5: 按钮 :active 按压 — 全局 CSS 规则

**选择**: 在 `.btn:active:not(:disabled)` 上统一添加 `transform: scale(0.96)`，按压感适用于所有按钮变体。hover 发光通过为 secondary/danger/success 补充 `box-shadow` 实现。

**理由**: 一条 CSS 规则覆盖所有按钮，零 JS。

### D6: 列表行 hover — translateY + accent 左条

**选择**: `.detection-item:hover` 增加 `translateY(-1px)`；`.waf-rule-row:hover` 增加左侧 2px accent 条 + 背景变化；`.server-card:hover` 已有 translateY 效果，仅统一时序。

**理由**: 与 provider-card 的 hover 模式保持一致。

## Risks / Trade-offs

- **[Tab 指示条初始位置]** → 页面加载时需确保 indicator 正确定位到默认 active tab（"态势感知"），`initTabs()` 中初始化
- **[Modal 关闭动画与快速连续操作]** → 如果用户在动画未结束时再次点击打开，需要先清除 `.modal-closing` class。Mitigation: `animationend` 前移除 class
- **[5 秒刷新重绘]** → 自动刷新可能重建列表项 DOM，列表行 hover 的 translateY 不受影响（纯 CSS）；但 Tab 指示条位置不会被刷新影响（tab 不变）
- **[加载按钮与重复点击]** → loading 态需 disabled 按钮防止重复提交
