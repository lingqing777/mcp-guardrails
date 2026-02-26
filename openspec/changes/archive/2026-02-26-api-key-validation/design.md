## Context

WAF2 的 LLM 语义分析依赖用户在 Dashboard 配置的 API Key。当前配置保存流程不做任何校验——任意字符串都会被接受。一旦保存了无效 Key，`call_llm()` 调用 LLM API 失败后静默返回 `"PASS"`（见 `waf2_proxy.py` 约 270 行），导致 WAF2 的全部安全检测形同虚设，但用户毫不知情。

现有的 `/waf2/test-llm` 端点已经能验证 Key 的真实可用性，但保存配置时未调用它。

## Goals / Non-Goals

**Goals:**
- 保存 LLM 配置前，用真实 LLM 调用验证 API Key 可用性，失败时警告用户
- `call_llm()` 失败时返回明确的 `"ERROR"` 状态（区别于 `"PASS"`），proxy 层记录但放行
- WAF2 stats 新增 `llm_errors` 计数，通过现有 `/waf2/stats` 和 `/waf2/dashboard` 接口暴露
- Dashboard 态势感知面板根据 `llm_errors` 展示 LLM 健康状态告警

**Non-Goals:**
- 不做 API Key 格式的正则校验（各家 provider 格式不统一且会变化，不可靠）
- 不在 LLM 失败时阻断请求（避免因 LLM 服务抖动导致全站不可用）
- 不改动 WAF1 的 CallChain 检测逻辑（独立问题，另行处理）
- 不加密存储 API Key（超出当前范围）

## Decisions

### 1. 验证方式：真实连通性测试，而非正则校验

**选择**：保存前调用已有的 `/waf2/test-llm` 接口做真实验证。

**理由**：regex 格式校验看似简单，但 15+ 个 provider 的 key 格式各异且可能变化，`custom` provider 更无法预知格式。真实调用是唯一可靠的验证方式，且接口已经存在，不需要后端改动。

**替代方案（否决）**：前端 regex 校验 —— 维护成本高、误报率高、无法确认 key 真正有效。

### 2. 验证失败策略：警告但允许强制保存

**选择**：测试失败时弹出警告对话框，用户可选择"仍然保存"或"取消"。

**理由**：用户可能在离线环境预配置、LLM 服务可能临时不可达。强制阻断会影响配置灵活性。

### 3. call_llm() 失败返回值：新增 `"ERROR"` 状态

**选择**：`call_llm()` 失败时返回字符串 `"ERROR"` 而非 `"PASS"`。proxy 层识别 `"ERROR"` 后仍然放行请求，但计入 `stats['llm_errors']`。

**理由**：需要区分"LLM 判定为安全"和"LLM 调不通"。当前的 `"PASS"` 让两者无法区分，stats 也无法反映真实情况。

**替代方案（否决）**：返回 `"BLOCK"` —— 会因 LLM 服务抖动导致全站不可用，不可接受。

### 4. 告警展示位置：态势感知面板顶部 banner

**选择**：在态势感知面板（默认首页）顶部加一条条件渲染的警告 banner，当 `llm_errors > 0` 时显示。

**理由**：态势感知是默认 Tab，用户一进来就能看到。不需要新增 Tab 或弹窗，改动最小。

## Risks / Trade-offs

- **test-llm 调用增加保存延迟** → 可接受，保存配置是低频操作，且 test-llm 超时设为 10s
- **LLM 服务临时抖动会触发误告警** → `llm_errors` 是累计计数，Dashboard 可在刷新时重置视觉状态；后续可考虑加"连续 N 次失败"阈值
- **stats 接口返回结构变化** → `llm_errors` 是新增字段，不影响已有字段，向后兼容
