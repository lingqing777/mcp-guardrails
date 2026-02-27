## Why

态势感知全屏面板（Monitor）存在多处数据源错误，导致攻击日志缺失 WAF1 记录、威胁等级只统计 WAF2 severity、OWASP 攻击分类图表永远为空。面向裁判演示时，这直接影响系统可信度。

## What Changes

- **修复攻击日志流（Log Stream）**：将 WAF1 数据源从 `/api/waf1/history`（调用链原始记录）改为使用 `/api/waf1/dashboard` 中的 `recentDetections`，使 WAF1 拦截事件正确出现在日志流中
- **修复威胁等级面板（Threat Level）**：补全 WAF1 severity 数据路径 `waf1.last24h.bySeverity`，使 critical/high/medium/low 计数包含双层数据
- **修复 OWASP 攻击分类图表**：从 WAF1 `last24h.byCategory` + WAF2 `by_category` 构建 OWASP 聚合数据，替代当前不存在的 `waf1.stats.owasp` 路径
- **优化 monitorRefresh 数据传递**：将 `w1Dashboard` 传入所有子函数（替代 `w1History`），去掉多余的 `/api/waf1/history` 请求

## Capabilities

### New Capabilities

（无新增能力）

### Modified Capabilities

- `dashboard`: 修复态势感知面板的数据源映射，使 WAF1 + WAF2 双层数据正确聚合

## Impact

- **前端**：`mcp-hub/src/dashboard/app.js` — `monitorRefresh()`、`monitorUpdateLogStream()`、`monitorUpdateThreatLevel()`、`monitorUpdateOwaspChart()` 四个函数
- **后端**：无改动，WAF1/WAF2 API 返回的数据已包含所需字段
- **Docker**：无影响
- **刷新机制**：态势感知面板 2.5s 刷新周期不变，去掉 `/api/waf1/history` 请求后减少一次网络往返
