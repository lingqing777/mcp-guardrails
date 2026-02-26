## Why

现有 Dashboard 是管理后台（配置开关、统计数据、Server 管理），面向日常操作。但项目是信安作品赛参赛作品，需要在答辩时给裁判展示实时攻防效果。当前缺少一个专门的**安全态势感知大屏**——能在演示时一眼展示双层 WAF 的拦截效果、攻击分布、防护拓扑和实时日志流。这是答辩加分最大的一项，直接决定裁判对项目"工程完成度"和"视觉冲击力"的第一印象。

## What Changes

- 在现有 Dashboard 中新增**"态势感知"Tab**，作为第一个 Tab 默认激活，用户登录后第一眼看到
- Tab 内容包含 5 个可视化面板（CSS Grid 布局）：
  - **实时攻击日志流**：滚动展示最新拦截事件，新攻击红色闪烁
  - **双层防护拓扑图**：Agent → WAF1 → MCP Server → WAF2 → Target，节点实时变色
  - **威胁等级仪表盘**：severity 计数 + 总拦截率
  - **OWASP 分类统计**：横向柱状图
  - **WAF1 vs WAF2 拦截对比**：双层互补效果可视化
- 面板右上角有**"全屏"按钮**，点击后：
  - 使用 Fullscreen API 进入浏览器真全屏
  - Header 和 Tab 栏用 CSS transition 丝滑淡出/滑走
  - 面板平滑扩展填满整个视口
  - 出现浮动的"退出全屏"按钮，ESC 键也可退出
  - 退出时 Header/Tab 丝滑回来，面板平滑收缩
- **不新增独立页面**，不新增路由，零新窗口，始终同一个 DOM
- 数据复用现有 API，Tab 激活时 2.5 秒刷新，切走时停止
- 删除已实现的独立 `/monitor` 路由和 monitor.html/css/js 文件

## Capabilities

### New Capabilities
- `display-screen`: 安全态势感知展示面板，作为 Dashboard 第一个 Tab 嵌入，支持全屏模式

### Modified Capabilities
- `dashboard`: 新增"态势感知"Tab 作为默认首页，Tab 栏新增全屏切换能力

## Impact

- **修改文件**：
  - `mcp-hub/src/dashboard/index.html` — 新增态势感知 Tab 面板 HTML + 全屏按钮
  - `mcp-hub/src/dashboard/styles.css` — 新增面板样式、全屏过渡动画
  - `mcp-hub/src/dashboard/app.js` — 新增态势感知数据刷新逻辑、全屏切换逻辑
  - `mcp-hub/src/server.js` — 删除 `/monitor` 路由
- **删除文件**：`mcp-hub/src/dashboard/monitor.html`、`monitor.js`、`monitor.css`
- **API**：不需要新增，复用现有端点
- **Docker**：不需要修改
- **路由位置**：无新路由，删除 `/monitor`
- **Dashboard 刷新**：态势感知 Tab 激活时独立 2.5 秒刷新，其他 Tab 保持 5 秒
