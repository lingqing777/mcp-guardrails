## 0. 清理第一轮实现

- [x] 0.1 删除 `mcp-hub/src/dashboard/monitor.html`
- [x] 0.2 删除 `mcp-hub/src/dashboard/monitor.js`
- [x] 0.3 删除 `mcp-hub/src/dashboard/monitor.css`
- [x] 0.4 删除 `mcp-hub/src/server.js` 中的 `/monitor` 路由
- [x] 0.5 删除 `mcp-hub/src/dashboard/index.html` Header 中的"展示大屏"独立链接
- [x] 0.6 删除 `mcp-hub/src/dashboard/styles.css` 中的 `.monitor-link` 样式

## 1. HTML 结构

- [x] 1.1 在 `mcp-hub/src/dashboard/index.html` Tab 栏最前面新增 `<div class="tab active" data-tab="monitor">态势感知</div>`，原"总览"Tab 移除 `active` class
- [x] 1.2 在 `index.html` 中 `#overview-panel` 之前新增 `<div id="monitor-panel" class="tab-content">` 面板，包含 5 个可视化区域的 HTML（攻击日志、拓扑 SVG、威胁等级、OWASP 图表、WAF 对比）
- [x] 1.3 在 monitor-panel 右上角添加"全屏"按钮；在 body 末尾添加浮动"退出全屏"按钮（默认隐藏）

## 2. CSS 样式

- [x] 2.1 在 `mcp-hub/src/dashboard/styles.css` 末尾新增态势感知面板样式区块：CSS Grid 五宫格布局、面板卡片样式（与现有 card 风格一致）
- [x] 2.2 新增全屏模式样式：`body.monitor-fullscreen` 时 Header/Tab 的 `opacity: 0; transform: translateY(-100%); pointer-events: none` 过渡，monitor-panel 的 `position: fixed; inset: 0; z-index: 1000` 扩展
- [x] 2.3 所有全屏相关过渡使用 `transition: all 0.4s cubic-bezier(0.4,0,0.2,1)`
- [x] 2.4 新增攻击日志动画：`@keyframes logSlideIn`（入场）+ `@keyframes logFlash`（红色脉冲）
- [x] 2.5 新增拓扑节点脉冲动画：`@keyframes nodePulse`（拦截时红色脉冲 2s）
- [x] 2.6 新增 `prefers-reduced-motion` 降级
- [x] 2.7 新增浮动退出按钮样式（fixed 定位、半透明背景、hover 效果）

## 3. JS 逻辑 — 全屏切换

- [x] 3.1 在 `mcp-hub/src/dashboard/app.js` 中新增 `enterMonitorFullscreen()` 函数：给 body 加 `monitor-fullscreen` class + 调用 `document.documentElement.requestFullscreen()`
- [x] 3.2 新增 `exitMonitorFullscreen()` 函数：移除 class + 调用 `document.exitFullscreen()`
- [x] 3.3 监听 `fullscreenchange` 事件：浏览器退出全屏时（ESC 键）自动移除 `monitor-fullscreen` class

## 4. JS 逻辑 — 数据层

- [x] 4.1 在 `app.js` 中新增 `monitorRefresh()` 函数：并行请求 `/api/waf1/dashboard`、WAF2 dashboard、`/api/waf1/history`、`/api/servers`
- [x] 4.2 新增态势感知 Tab 的独立刷新定时器（2.5s），仅在 Tab 激活时运行：Tab 切入时 `setInterval`，切走时 `clearInterval`
- [x] 4.3 适配现有 Tab 切换逻辑：在 Tab 切换回调中检测 `data-tab="monitor"`，启停刷新

## 5. JS 逻辑 — 面板渲染

- [x] 5.1 实现攻击日志渲染：合并 WAF1 history + WAF2 detections，按时间倒序，最多 50 条，新条目带 flash 动画，无数据时显示占位
- [x] 5.2 实现拓扑图更新：Server 在线数、WAF1/WAF2 状态指示灯、新拦截时节点/连线红色脉冲
- [x] 5.3 实现威胁等级渲染：severity 计数（合并 WAF1+WAF2）+ 进度条 + 拦截率百分比 + 数字平滑计数动画
- [x] 5.4 实现 OWASP 图表：Chart.js 横向柱状图，Grafana 色系，刷新时 `update()` 平滑更新
- [x] 5.5 实现 WAF1 vs WAF2 对比图表：Chart.js 双组柱状图，合并 byRule/byDetector 和 by_category，标注各层总拦截数

## 6. 验证

- [ ] 6.1 验证登录后默认显示"态势感知"Tab
- [ ] 6.2 验证 Tab 切换正常（态势感知 ↔ 其他 Tab），数据刷新正确启停
- [ ] 6.3 验证点击"全屏"按钮：Header/Tab 丝滑淡出，面板扩展填满视口，退出按钮出现
- [ ] 6.4 验证点击"退出全屏"和按 ESC：Header/Tab 丝滑回来，面板收缩
- [ ] 6.5 验证 1920x1080 下布局完整，无溢出
