## MODIFIED Requirements

### Requirement: 态势感知面板数据层

层级：Dashboard

态势感知全屏面板（Monitor）的 `monitorRefresh()` SHALL 每 2.5 秒从 3 个 API 拉取数据并分发给 5 个子渲染函数：

| API | 变量 | 用途 |
|-----|------|------|
| `/api/waf1/dashboard` | `w1Dashboard` | WAF1 统计 + recentDetections |
| `${WAF2_BASE}/waf2/dashboard` | `w2Dashboard` | WAF2 统计 + recent_detections |
| `/api/servers` | `serversData` | MCP Server 拓扑 |

`/api/waf1/history` 请求 SHALL 被移除（该接口返回调用链原始记录，非攻击检测数据）。

子函数签名 SHALL 为：
- `monitorUpdateLogStream(w1Dashboard, w2Dashboard)`
- `monitorUpdateTopology(w1Dashboard, w2Dashboard, serversData)`
- `monitorUpdateThreatLevel(w1Dashboard, w2Dashboard)`
- `monitorUpdateOwaspChart(w1Dashboard, w2Dashboard)`
- `monitorUpdateCompareChart(w1Dashboard, w2Dashboard)`

#### Scenario: monitorRefresh 发起 3 个并行请求
- **WHEN** 态势感知面板处于全屏状态且定时器触发刷新
- **THEN** `monitorRefresh()` SHALL 发起 3 个 `fetch` 请求（waf1/dashboard, waf2/dashboard, servers）
- **AND** SHALL NOT 请求 `/api/waf1/history`

#### Scenario: w1Dashboard 传入所有子函数
- **WHEN** 3 个 API 响应返回
- **THEN** `w1Dashboard` SHALL 作为第一参数传入 `monitorUpdateLogStream`、`monitorUpdateThreatLevel`、`monitorUpdateOwaspChart`
- **AND** `monitorUpdateLogStream` 不再接收 `w1History` 参数

### Requirement: 攻击日志流 Log Stream 数据源

层级：Dashboard

`monitorUpdateLogStream(w1Dashboard, w2Dashboard)` SHALL 从两个 dashboard 响应中提取攻击检测记录：

- WAF1 数据源：`w1Dashboard.recentDetections[]`（每条含 category, severity, reason, labels, timestamp）
- WAF2 数据源：`w2Dashboard.recent_detections[]`（每条含 category, severity, reason, timestamp）

两层记录 SHALL 合并后按 timestamp 降序排列，最多显示 50 条。

#### Scenario: WAF1 检测事件出现在日志流中
- **WHEN** WAF1 已拦截攻击且 `w1Dashboard.recentDetections` 包含记录
- **THEN** 日志流 SHALL 显示每条 WAF1 记录，source 标记为 "WAF1"
- **AND** category 取自 `detection.category`，severity 取自 `detection.severity`，reason 取自 `detection.reason`

#### Scenario: WAF2 检测事件出现在日志流中
- **WHEN** WAF2 已拦截攻击且 `w2Dashboard.recent_detections` 包含记录
- **THEN** 日志流 SHALL 显示每条 WAF2 记录，source 标记为 "WAF2"

#### Scenario: 双层记录按时间混合排序
- **WHEN** WAF1 和 WAF2 都有检测记录
- **THEN** 所有记录 SHALL 合并为一个列表并按 timestamp 降序排列
- **AND** 日志流显示最多 50 条记录

#### Scenario: 无检测记录时显示空态
- **WHEN** WAF1 和 WAF2 均无检测记录
- **THEN** 日志流 SHALL 显示 "暂无攻击记录" 空态占位

### Requirement: 威胁等级面板 Threat Level 数据路径

层级：Dashboard

`monitorUpdateThreatLevel(w1Dashboard, w2Dashboard)` SHALL 从正确的数据路径读取 severity 分布：

- WAF1 severity 数据路径：`w1Dashboard.last24h.bySeverity`
- WAF2 severity 数据路径：`w2Dashboard.by_severity`

四个等级（critical / high / medium / low）的计数 SHALL 聚合双层数据。

#### Scenario: WAF1 severity 计数被正确读取
- **WHEN** WAF1 dashboard 返回 `{ last24h: { bySeverity: { high: 3, medium: 5 } } }`
- **THEN** 威胁等级面板 high 计数 SHALL 包含 WAF1 的 3 条
- **AND** medium 计数 SHALL 包含 WAF1 的 5 条

#### Scenario: 双层 severity 聚合
- **WHEN** WAF1 bySeverity 为 `{ high: 3 }` 且 WAF2 by_severity 为 `{ high: 2, critical: 1 }`
- **THEN** 面板显示 critical=1, high=5, medium=0, low=0

#### Scenario: WAF1 数据不可用时降级
- **WHEN** WAF1 dashboard API 返回 null
- **THEN** 威胁等级面板 SHALL 仅显示 WAF2 数据，不报错

### Requirement: OWASP 攻击分类图表数据构建

层级：Dashboard

`monitorUpdateOwaspChart(w1Dashboard, w2Dashboard)` SHALL 从双层分类数据构建 OWASP 聚合：

1. 读取 WAF1 `last24h.byCategory`，通过前端映射表转换为 OWASP 编号
2. 读取 WAF2 `by_category`，通过前端映射表转换为 OWASP 编号
3. 相同 OWASP 编号的计数 SHALL 累加

前端 MUST 维护以下 category → OWASP 映射：

| WAF1 Category | OWASP |
|---|---|
| sqlInjection | A03:2021 |
| shellInjection | A03:2021 |
| xss | A03:2021 |
| pathTraversal | A01:2021 |
| sensitiveFiles | A01:2021 |
| ssrf | A10:2021 |
| dataExfiltration | A01:2021 |
| dangerousOperations | A03:2021 |
| protocolAttacks | A05:2021 |
| secrets | A02:2021 |
| pii | A02:2021 |

| WAF2 Category | OWASP |
|---|---|
| sql_injection | A03:2021 |
| command_injection | A03:2021 |
| xss | A03:2021 |
| path_traversal | A01:2021 |
| ssrf | A10:2021 |
| prompt_injection | LLM01 |
| sensitive_data_exposure | A02:2021 |

#### Scenario: WAF1 分类映射为 OWASP
- **WHEN** WAF1 byCategory 为 `{ sqlInjection: 3, pathTraversal: 2 }`
- **THEN** OWASP 图表 SHALL 显示 A03:2021=3, A01:2021=2

#### Scenario: 双层数据聚合到同一 OWASP 编号
- **WHEN** WAF1 byCategory 含 `sqlInjection: 3` 且 WAF2 by_category 含 `sql_injection: 2`
- **THEN** OWASP 图表中 A03:2021 SHALL 为 5（3+2）

#### Scenario: WAF2 prompt_injection 映射为 LLM01
- **WHEN** WAF2 by_category 含 `prompt_injection: 4`
- **THEN** OWASP 图表 SHALL 包含 LLM01=4

#### Scenario: 双层数据均为空时显示占位
- **WHEN** WAF1 和 WAF2 的分类数据均为空或 null
- **THEN** OWASP 图表 SHALL 显示 "暂无数据" 占位
