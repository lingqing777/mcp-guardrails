## ADDED Requirements

### Requirement: CFG-45 保存前 LLM 配置验证流程
Dashboard 前端在调用 `POST /api/config/waf2` 保存 LLM 配置前，MUST 先调用 WAF2 的 test-llm 接口进行连通性验证。此验证在前端发起，不改变后端 API 行为。

#### Scenario: 前端保存流程
- **WHEN** 用户在 Dashboard 点击保存 LLM 配置
- **THEN** 前端 MUST 先 POST 到 `/waf2/test-llm`（通过 WAF2 代理）
- **AND** 仅在测试通过或用户确认强制保存后，才调用 `POST /api/config/waf2`

#### Scenario: 后端保存接口不变
- **WHEN** `POST /api/config/waf2` 收到请求
- **THEN** 后端行为与现有逻辑完全一致，不增加校验
