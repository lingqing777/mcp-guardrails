## 1. 简化 monitorRefresh 数据流

- [ ] 1.1 在 `monitorRefresh()` 中移除 `/api/waf1/history` 请求，将 `Promise.all` 从 4 个请求改为 3 个（w1Dashboard, w2Dashboard, serversData）
- [ ] 1.2 修改 `monitorUpdateLogStream` 调用，第一参数从 `w1History` 改为 `w1Dashboard`
- [ ] 1.3 修改 `monitorUpdateOwaspChart` 调用，增加第二参数 `w2Dashboard`

## 2. 修复攻击日志流 Log Stream

- [ ] 2.1 修改 `monitorUpdateLogStream(w1Dashboard, w2Dashboard)` 函数签名，第一参数从 `waf1History` 改为 `waf1`
- [ ] 2.2 将 WAF1 数据提取逻辑从 `waf1History.history[]` 改为 `waf1.recentDetections[]`，字段取 category/severity/reason/timestamp（使用 labels 结构中的字段）

## 3. 修复威胁等级 Threat Level

- [ ] 3.1 修改 `monitorUpdateThreatLevel` 中 WAF1 severity 数据路径，将 `waf1?.summary?.bySeverity` 改为 `waf1?.last24h?.bySeverity`

## 4. 修复 OWASP 攻击分类图表

- [ ] 4.1 在 `app.js` 中添加 `MONITOR_WAF1_OWASP_MAP` 和 `MONITOR_WAF2_OWASP_MAP` 两个 category → OWASP 映射常量
- [ ] 4.2 重写 `monitorUpdateOwaspChart(w1Dashboard, w2Dashboard)` — 从 `w1Dashboard.last24h.byCategory` + `w2Dashboard.by_category` 读取分类计数，通过映射表聚合为 OWASP 编号计数，传入 Chart.js
