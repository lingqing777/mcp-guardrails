## MODIFIED Requirements

### Requirement: WAF2-23
LLM API 调用失败时 MUST 放行请求，但 MUST 返回 `"ERROR"` 状态（而非 `"PASS"`），并将错误计入 `stats['llm_errors']` 计数器。proxy 层 MUST 区分 `"PASS"`、`"BLOCK"` 和 `"ERROR"` 三种状态。

#### Scenario: LLM 调用失败 — 放行但标记 ERROR
- **WHEN** WAF2 已启用，`call_llm()` 因 API Key 无效或网络错误抛出异常
- **THEN** `call_llm()` MUST 返回字符串 `"ERROR"`
- **AND** `stats['llm_errors']` MUST 递增 1
- **AND** proxy MUST 放行请求到上游
- **AND** 日志 MUST 打印 `[WAF2] ⚠️ LLM 调用失败: {error}`

#### Scenario: LLM 调用成功 — 正常流程不变
- **WHEN** `call_llm()` 正常返回 `"PASS"` 或 `"BLOCK|..."`
- **THEN** proxy 按原有逻辑处理（放行或拦截）
- **AND** `stats['llm_errors']` 不变

## ADDED Requirements

### Requirement: WAF2-60 stats 新增 llm_errors 字段
WAF2 stats MUST 新增 `llm_errors` 字段，追踪 LLM 调用失败次数。该字段 MUST 通过 `GET /waf2/stats` 和 `GET /waf2/dashboard` 接口暴露。`POST /waf2/reset` MUST 将 `llm_errors` 重置为 0。

#### Scenario: stats 接口返回 llm_errors
- **WHEN** 调用 `GET /waf2/stats`
- **THEN** 响应 JSON MUST 包含 `llm_errors` 字段（整数）

#### Scenario: reset 清零 llm_errors
- **WHEN** 调用 `POST /waf2/reset`
- **THEN** `stats['llm_errors']` MUST 重置为 0
