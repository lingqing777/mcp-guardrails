## Context

态势感知全屏面板（Monitor）由 `monitorRefresh()` 驱动，每 2.5 秒从 4 个 API 拉取数据分发给 5 个子渲染函数。当前数据路径存在 3 处断裂：

1. **Log Stream** 使用 `/api/waf1/history`（调用链原始数组 `[{tool, args, ts}]`），但代码期望 `{history: [{timestamp, category, severity, reason}]}`
2. **Threat Level** 查找 `waf1.summary.bySeverity`，实际在 `waf1.last24h.bySeverity`
3. **OWASP Chart** 查找 `waf1.stats.owasp`，WAF1 API 无此字段；且未接入 WAF2 数据

后端 API 已返回足够数据（WAF1 dashboard 含 `recentDetections` / `last24h.bySeverity` / `last24h.byCategory`，WAF2 dashboard 含 `by_category` / `by_severity`），不需要后端改动。

## Goals / Non-Goals

**Goals:**
- 修复 3 处数据路径错误，使 Monitor 面板正确聚合 WAF1 + WAF2 双层数据
- 去掉多余的 `/api/waf1/history` 请求，减少网络往返
- OWASP 图表从双层分类数据构建，映射 WAF1 规则名 + WAF2 category → OWASP 编号

**Non-Goals:**
- 不改动后端 API 返回结构
- 不改变 Monitor 面板的视觉设计和布局
- 不处理小样本拦截率显示问题（数学上正确，属 UX 优化范畴）

## Decisions

### 1. Log Stream 数据源：用 w1Dashboard.recentDetections 替代 w1History

**选择**：去掉 `/api/waf1/history` 请求，改用已有的 `w1Dashboard.recentDetections`

**理由**：
- `/api/waf1/history` 返回的是调用链原始记录（所有请求），不是攻击检测记录
- `w1Dashboard.recentDetections` 已包含 category、severity、reason、labels（含 MITRE、OWASP），数据结构与 Monitor Log Stream 渲染期望一致
- 减少一次 fetch 调用

**替代方案**：修改 `/api/waf1/history` 返回格式 → 需要改后端，且与 API 语义不符

### 2. OWASP 聚合：前端从 category 映射

**选择**：在前端维护 WAF1 rule category → OWASP 映射表，与 WAF2 detection.owasp 字段合并

**理由**：
- WAF1 后端 `stats.js` 已有 `CATEGORY_SEVERITY` 映射但无 OWASP 聚合
- WAF2 的 `ATTACK_CATEGORIES` 已含 OWASP 编号
- 在前端做映射，无需改后端，两层数据在一处聚合

**映射表**：
```
WAF1 categories:         OWASP
sqlInjection          → A03:2021
shellInjection        → A03:2021
xss                   → A03:2021
pathTraversal         → A01:2021
sensitiveFiles        → A01:2021
ssrf                  → A10:2021
dataExfiltration      → A01:2021
dangerousOperations   → A03:2021
protocolAttacks       → A05:2021
secrets               → A02:2021
pii                   → A02:2021

WAF2 categories (from detection.owasp field):
sql_injection         → A03:2021
command_injection     → A03:2021
xss                   → A03:2021
path_traversal        → A01:2021
ssrf                  → A10:2021
prompt_injection      → LLM01
sensitive_data_exposure → A02:2021
```

### 3. monitorRefresh 简化

**选择**：去掉 `w1History` 请求，只保留 3 个 fetch（w1Dashboard, w2Dashboard, serversData）

**改动**：
```
// Before: 4 个请求
[w1Dashboard, w2Dashboard, w1History, serversData]

// After: 3 个请求
[w1Dashboard, w2Dashboard, serversData]
```

函数签名调整：
- `monitorUpdateLogStream(w1Dashboard, w2Dashboard)` — 从两个 dashboard 取 recentDetections / recent_detections
- `monitorUpdateOwaspChart(w1Dashboard, w2Dashboard)` — 接入双层数据
- `monitorUpdateThreatLevel(w1Dashboard, w2Dashboard)` — 补全 `last24h.bySeverity` 路径

## Risks / Trade-offs

- **[WAF1 recentDetections 只保留最近 10 条]** → 与当前 Log Stream 显示上限 50 条不完全匹配，但对演示来说 10 条 WAF1 + 10 条 WAF2 已足够，且是已有后端限制
- **[前端 OWASP 映射需与后端保持同步]** → 如果 WAF1/WAF2 新增攻击类别，需要同步更新前端映射表。风险低，类别变动不频繁
