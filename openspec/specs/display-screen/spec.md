# 态势感知大屏 (Display Screen)

## Purpose

为 Dashboard 提供安全态势感知可视化大屏，作为 Dashboard 的第一个 Tab，集中展示实时攻击日志、防护拓扑、威胁等级、攻击分类统计等安全态势信息。

层级：Dashboard

## Requirements

### Requirement: 态势感知作为 Dashboard 第一个 Tab
Dashboard SHALL 新增"态势感知"Tab，位于所有 Tab 之前，作为默认激活的首页 Tab。

层级：Dashboard

#### Scenario: 用户登录后看到态势感知
- **WHEN** 用户登录并访问 Dashboard
- **THEN** "态势感知"Tab 默认激活，显示 5 个可视化面板

#### Scenario: 用户切换 Tab
- **WHEN** 用户点击"总览"等其他 Tab
- **THEN** 态势感知面板隐藏，对应 Tab 内容显示
- **WHEN** 用户点回"态势感知"Tab
- **THEN** 面板重新显示并恢复数据刷新

### Requirement: 实时攻击日志流面板
态势感知 Tab SHALL 包含实时攻击日志流面板，合并 WAF1 和 WAF2 的检测记录，按时间倒序展示最近 50 条。
每条日志 SHALL 显示时间戳、来源 [WAF1/WAF2]、类别、severity 徽章和 reason。
新攻击 SHALL 以红色闪烁动画出现。

层级：Dashboard

### Requirement: 双层防护拓扑图面板
态势感知 Tab SHALL 包含 SVG 拓扑图，展示 Agent → WAF1 → MCP Servers → WAF2 → Target 的数据流。
节点 SHALL 显示在线/离线状态，拦截时节点和连线 SHALL 触发红色脉冲动画。

层级：Dashboard

### Requirement: 威胁等级仪表盘面板
态势感知 Tab SHALL 包含威胁等级面板，显示 CRITICAL/HIGH/MEDIUM/LOW 四级计数和进度条，以及总拦截率百分比。数字变化 SHALL 有平滑计数动画。

层级：Dashboard

### Requirement: OWASP 分类统计面板
态势感知 Tab SHALL 包含 OWASP 攻击分类横向柱状图（Chart.js），使用 Grafana 色系配色，实时更新。

层级：Dashboard

### Requirement: WAF1 vs WAF2 拦截对比面板
态势感知 Tab SHALL 包含双组柱状图对比 WAF1 和 WAF2 的拦截分类，标注各层总拦截数。

层级：Dashboard

### Requirement: 全屏模式
态势感知 Tab SHALL 提供"全屏"按钮，点击后：
- 使用 Fullscreen API 进入浏览器真全屏
- Header 和 Tab 栏 SHALL 用 CSS transition 丝滑淡出
- 面板 SHALL 平滑扩展填满整个视口
- SHALL 出现浮动的"退出全屏"按钮
- ESC 键 SHALL 也能退出全屏
- 退出时 Header/Tab SHALL 丝滑回来，面板平滑收缩
全屏过渡 SHALL 使用 `transition: all 0.4s cubic-bezier(0.4,0,0.2,1)` 或同等平滑效果。

层级：Dashboard

#### Scenario: 进入全屏
- **WHEN** 用户点击"全屏"按钮
- **THEN** 浏览器进入全屏，Header/Tab 丝滑淡出，面板扩展填满视口，出现退出按钮

#### Scenario: 退出全屏（按钮）
- **WHEN** 用户点击"退出全屏"按钮
- **THEN** 浏览器退出全屏，Header/Tab 丝滑回来，面板收缩回 Tab 内容区

#### Scenario: 退出全屏（ESC 键）
- **WHEN** 用户按 ESC 键
- **THEN** 效果同点击退出按钮

### Requirement: 态势感知刷新策略
态势感知 Tab 激活时 SHALL 以 2.5 秒间隔刷新数据。
切换到其他 Tab 时 SHALL 停止刷新。
全屏模式下 SHALL 继续刷新。

层级：Dashboard
