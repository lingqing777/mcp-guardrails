## Why

用户在 Dashboard 保存错误格式的 API Key 时系统不报错，导致 WAF2 的 LLM 检测静默失效（`call_llm()` 失败后返回 `"PASS"`）。用户完全不知道安全防护已经瘫痪，直到出现"连续发两个一模一样的请求一个成功一个失败"等诡异现象才发觉异常。

## What Changes

- **保存前连通性测试**：Dashboard 保存 LLM 配置时，先调用 `/waf2/test-llm` 做真实连通性验证，失败则警告用户（仍允许强制保存）
- **LLM 调用失败可见化**：WAF2 `call_llm()` 失败不再静默返回 `"PASS"`，改为返回 `"ERROR"` 并计入 stats，proxy 层区分处理
- **Dashboard 健康告警**：态势感知面板展示 WAF2 LLM 健康状态，连续失败时显示醒目警告，引导用户检查 API Key

## Capabilities

### New Capabilities

_无新增独立能力_

### Modified Capabilities

- `waf2`: `call_llm()` 失败处理策略从静默 PASS 改为 ERROR + 统计，proxy 层增加降级标记
- `dashboard`: 配置保存流程增加 LLM 连通性预检，态势感知面板增加 LLM 健康状态告警
- `config`: WAF2 配置保存 API 不变，前端调用流程变更（先 test 再 save）

## Impact

- **waf2/waf2_proxy.py**：`call_llm()` 返回值新增 `"ERROR"` 状态，`proxy()` 函数增加降级处理逻辑，stats 新增 `llm_errors` 字段
- **mcp-hub/src/dashboard/app.js**：`applyConfig()` 流程变更（插入 test-llm 调用），态势感知面板新增 LLM 健康状态组件
- **mcp-hub/src/dashboard/styles.css**：新增告警样式
- 不涉及 Docker 配置变更，不涉及新路由，不影响 server.js 路由顺序
- Dashboard 5 秒刷新机制不受影响（告警状态随 stats 接口一起返回）
