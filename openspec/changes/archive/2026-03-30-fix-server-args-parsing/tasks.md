## 1. UI 输入形式调整

- [x] 1.1 将 Dashboard 中 `stdio` server 的 `args` 输入区改为 `textarea`，placeholder 使用 JSON 数组示例

## 2. 保存逻辑校验

- [x] 2.1 在 `mcp-hub/src/dashboard/app.js` 中将 `args` 保存逻辑改为 `JSON.parse`
- [x] 2.2 当 `args` parse 失败时，提示“参数 JSON 格式无效”
- [x] 2.3 当 `args` parse 成功但结果不是数组时，提示“参数必须是 JSON 数组格式”

## 3. 编辑回显

- [x] 3.1 编辑已有 `stdio` server 时，将 `args` 以格式化 JSON 字符串回填到输入框

## 4. 验证

注：4.1 已通过认证配置 API 做往返验证（新增 `temp-json-args` → 读取配置 → 删除临时 server）。4.2 / 4.3 通过前端代码路径核实：`saveServer()` 对非法 JSON 会 `alert + return`，`editCurrentServer()` 会对 `serverConfig.args` 执行 `JSON.stringify(..., null, 2)` 回填。

- [x] 4.1 新建 `stdio` server 时输入合法 JSON 数组，确认可成功保存
- [x] 4.2 新建 `stdio` server 时输入非法 JSON，确认前端阻止保存并提示错误
- [x] 4.3 编辑已有 `stdio` server，确认 `args` 以 JSON 数组格式正确回显
