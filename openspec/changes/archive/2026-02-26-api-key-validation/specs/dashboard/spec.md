## ADDED Requirements

### Requirement: DASH-60 保存 LLM 配置前连通性预检
Dashboard 保存 LLM 配置时（`applyConfig()` 流程），MUST 在实际保存前调用 `/waf2/test-llm` 接口验证 API Key 可用性。

#### Scenario: API Key 有效 — 正常保存
- **WHEN** 用户点击保存，test-llm 返回成功
- **THEN** 配置正常保存
- **AND** 显示成功提示

#### Scenario: API Key 无效 — 警告后允许强制保存
- **WHEN** 用户点击保存，test-llm 返回失败或超时
- **THEN** MUST 弹出警告对话框，内容包含错误信息
- **AND** 对话框提供"仍然保存"和"取消"两个选项
- **AND** 用户选择"仍然保存"时正常保存配置
- **AND** 用户选择"取消"时留在编辑状态，不保存

#### Scenario: Ollama Provider — 跳过预检
- **WHEN** 用户选择的 Provider 为 Ollama 且 API Key 为空
- **THEN** 跳过 test-llm 验证，直接保存

#### Scenario: test-llm 网络不可达 — 视为验证失败
- **WHEN** test-llm 接口本身不可达（WAF2 容器未启动）
- **THEN** 按验证失败处理，弹出警告对话框

### Requirement: DASH-61 态势感知 LLM 健康告警
态势感知面板 MUST 展示 WAF2 LLM 健康状态。当 WAF2 stats 中 `llm_errors > 0` 时，MUST 在面板顶部显示醒目的警告 banner。

#### Scenario: LLM 正常 — 无告警
- **WHEN** WAF2 stats 中 `llm_errors` 为 0
- **THEN** 态势感知面板不显示 LLM 告警 banner

#### Scenario: LLM 异常 — 显示告警
- **WHEN** WAF2 stats 中 `llm_errors > 0`
- **THEN** 态势感知面板顶部 MUST 显示警告 banner
- **AND** banner 文案 MUST 包含 "WAF2 LLM 检测不可用" 和 "请检查 API Key 配置"
- **AND** banner 样式 MUST 使用警告色调（amber/yellow），与现有 Grafana 暗色主题一致

#### Scenario: 告警随刷新更新
- **WHEN** Dashboard 5 秒自动刷新获取到新的 stats 数据
- **THEN** banner 显示状态 MUST 根据最新 `llm_errors` 值更新
