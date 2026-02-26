## Why

配置页面当前 5 个 section 全部展开堆叠，视觉上拥挤且缺乏层次感。只有「配置指引」一个 section 做了手风琴收起效果。将所有 section 统一改为可收缩手风琴，可以减少视觉噪音、突出当前关注区域，同时与已有的手风琴组件风格保持一致。

## What Changes

- 配置 Tab 内所有 5 个 `.config-section` 统一添加 chevron + 点击收缩/展开交互
- 防护模式、快速配置默认展开；配置指引、WAF 规则开关、数据管理默认收起
- section header hover 态增加背景色，提示可点击
- 重构 `toggleAccordion()` 为通用函数，不再硬编码 `config-guide`
- 展开/收起有 `max-height` + `opacity` 过渡动画

## Capabilities

### New Capabilities

_(无新 capability，复用现有 Dashboard UI 模式)_

### Modified Capabilities

- `dashboard`: 配置 Tab section 交互模式从静态堆叠变为手风琴收缩

## Impact

- `mcp-hub/src/dashboard/index.html` — 5 个 config-section header 添加 onclick + chevron
- `mcp-hub/src/dashboard/styles.css` — 新增 config-section 收缩动画样式、header hover 效果
- `mcp-hub/src/dashboard/app.js` — 重构 `toggleAccordion()`，新增初始化逻辑设置默认展开/收起状态
- 不影响 WAF1/WAF2 双层架构
- 不影响 Docker 配置
- 不影响 Dashboard 5 秒刷新机制
- 不涉及新路由
