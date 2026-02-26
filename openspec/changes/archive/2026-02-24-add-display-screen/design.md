## Context

MCP Guardrails Dashboard 是原生 JS + CSS + Chart.js 构建的 Tab 式管理后台，6 个 Tab（总览/MCP Servers/WAF1/WAF2/检测记录/配置）。用户登录后默认看到"总览"Tab。

第一轮实现时将态势感知做成了独立页面 `/monitor`（monitor.html + monitor.js + monitor.css），但用户反馈体验割裂——需要开新窗口。现在改为嵌入 Dashboard 作为第一个 Tab，并支持全屏模式。

## Goals / Non-Goals

**Goals:**
- 态势感知作为 Dashboard 第一个 Tab，默认激活
- 5 个面板嵌入 Tab 内容区（CSS Grid），与其他 Tab 无缝切换
- 全屏按钮：Fullscreen API + CSS transition 丝滑过渡（Header/Tab 淡出，面板扩展）
- 退出全屏：浮动退出按钮 + ESC 键，Header/Tab 丝滑回来
- Tab 激活时 2.5 秒刷新，切走时停止（避免浪费请求）
- 删除独立的 monitor.html/js/css 和 `/monitor` 路由

**Non-Goals:**
- 不引入 Vue/React 等框架
- 不新增独立页面或路由
- 不修改现有其他 Tab 的行为
- 不引入 Three.js / D3.js 等重型库

## Decisions

### Decision 1: 嵌入 Tab 而非独立页面

**选择**: 态势感知作为 index.html 中的 Tab 面板。

**备选方案**:
- A) 独立页面 `/monitor` → 体验割裂，需要切换窗口（已否决）
- B) 嵌入为 Tab + 全屏模式 → 统一体验，全屏时沉浸

**理由**: 用户体验一致性。所有功能在同一页面内切换，全屏模式满足答辩投屏需求。

### Decision 2: 全屏实现方案

**选择**: Fullscreen API + CSS class 切换 + transition 动画

```
正常模式:
  body 无特殊 class
  Header 可见, Tab 栏可见
  面板在 tab-content 内，高度 = 100vh - header - tabs

全屏模式:
  body.monitor-fullscreen
  Fullscreen API 激活浏览器真全屏
  Header: opacity 0 + translateY(-100%) + pointer-events none
  Tab 栏: opacity 0 + translateY(-100%) + pointer-events none
  面板容器: position fixed, inset 0, z-index 1000
  浮动退出按钮出现
```

所有过渡用 CSS `transition: all 0.4s cubic-bezier(0.4,0,0.2,1)`，丝滑不突兀。

Fullscreen API 退出时（ESC 键）通过 `fullscreenchange` 事件自动移除 class，恢复常态。

### Decision 3: 刷新策略

**选择**: Tab 激活时启动独立 2.5s 定时器，切走时清除。

现有 Dashboard 的 5 秒全局刷新机制不动。态势感知 Tab 有自己的 `setInterval`，只在 `data-tab="monitor"` 激活时运行。全屏模式下也保持刷新（因为 Tab 逻辑上仍然激活）。

### Decision 4: 代码组织

**选择**: 所有代码嵌入现有文件，不新增文件。

- HTML 面板 → `index.html` 中新增 `#monitor-panel` 的 `tab-content` div
- CSS 样式 → `styles.css` 末尾新增态势感知区块（从 monitor.css 迁移并适配）
- JS 逻辑 → `app.js` 中新增态势感知模块函数（数据获取、面板渲染、全屏切换）

**理由**: 与现有 Dashboard 架构一致（所有 Tab 都在同一套文件中），Tab 切换逻辑可以复用现有的 `data-tab` 机制。

### Decision 5: 布局适配

```
Tab 模式:
  高度 = calc(100vh - 48px header - 40px tabs - 24px padding)
  Grid: 3 列 2 行，攻击日志跨 2 行

全屏模式:
  高度 = 100vh（减去浮动退出按钮的空间）
  Grid: 同上，面板自动拉伸填满
```

CSS Grid 定义不变，只是容器高度变化，面板自适应。

## Risks / Trade-offs

**[app.js 膨胀]** → app.js 已 1400+ 行，再加态势感知逻辑约 200-300 行。可接受，因为都是独立函数，不与其他 Tab 逻辑交叉。未来可提取为独立模块但现在不必要。

**[styles.css 膨胀]** → 同上，新增约 200 行 CSS。通过注释区块隔离，不影响现有样式。

**[全屏兼容性]** → Fullscreen API 在现代浏览器（Chrome/Firefox/Edge）均支持。Safari 需要 `webkitRequestFullscreen` 前缀。本地演示环境以 Chrome 为主，兼容性风险低。

**[Tab 切换时的图表重建]** → Chart.js 实例在 Tab 首次激活时创建，切走不销毁（隐藏状态）。切回时直接 `update()` 数据，避免重复创建的性能开销。

## Open Questions

无。方案已确认。
