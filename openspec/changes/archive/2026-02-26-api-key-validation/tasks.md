## 1. WAF2 后端：call_llm() 失败处理 + stats

- [x] 1.1 `waf2/waf2_proxy.py` — stats 字典新增 `'llm_errors': 0` 初始字段
- [x] 1.2 `waf2/waf2_proxy.py` — `call_llm()` 函数：异常捕获分支中将 `stats['llm_errors'] += 1`，返回值从 `"PASS"` 改为 `"ERROR"`
- [x] 1.3 `waf2/waf2_proxy.py` — `proxy()` 函数（WAF2 启用路径）：请求分析结果为 `"ERROR"` 时，仍然放行（不 BLOCK），打印 `[WAF2] ⚠️ LLM 检测降级` 日志
- [x] 1.4 `waf2/waf2_proxy.py` — `/waf2/stats` 和 `/waf2/dashboard` 端点确认已包含 `llm_errors` 字段（因为 stats 字典直接序列化，新字段自动暴露）
- [x] 1.5 `waf2/waf2_proxy.py` — `/waf2/reset` 端点增加 `stats['llm_errors'] = 0` 重置逻辑

## 2. Dashboard 前端：保存前 LLM 连通性预检

- [x] 2.1 `mcp-hub/src/dashboard/app.js` — `applyConfig()` 函数：在调用 `api.waf2.updateConfig()` 之前，插入 test-llm 调用逻辑
- [x] 2.2 `mcp-hub/src/dashboard/app.js` — test-llm 失败时弹出确认对话框（使用现有的 toast/modal 机制或 `confirm()`），用户可选"仍然保存"或"取消"
- [x] 2.3 `mcp-hub/src/dashboard/app.js` — Ollama provider 且 API Key 为空时跳过 test-llm 验证

## 3. Dashboard 前端：态势感知 LLM 健康告警

- [x] 3.1 `mcp-hub/src/dashboard/index.html` — 态势感知面板顶部添加 LLM 告警 banner 容器（默认隐藏）
- [x] 3.2 `mcp-hub/src/dashboard/styles.css` — 告警 banner 样式：amber/yellow 警告色调，Grafana 暗色主题一致性，带过渡动画
- [x] 3.3 `mcp-hub/src/dashboard/app.js` — 数据刷新回调中读取 WAF2 stats 的 `llm_errors` 字段，`> 0` 时显示 banner，`= 0` 时隐藏
