## Context

Dashboard 中新增/编辑 MCP Server 时，`stdio` 类型的 `args` 原先是单行字符串输入。用户习惯输入：

```text
-y @modelcontextprotocol/server-filesystem /home/q1n9
```

但这种自由文本格式存在两个根本问题：

- 空格是否表示分隔符不稳定，参数值本身也可能包含空格
- 逗号分隔、空格分隔、引号包裹三种心智模型互相冲突，前后端很难无歧义解析

当前后端 `config/mcp-servers.json` 需要的是真正的 JSON 数组，最终仍要落成：

```json
["-y", "@modelcontextprotocol/server-filesystem", "/home/q1n9"]
```

## Goals / Non-Goals

**Goals:**
- 消除 `args` 输入格式歧义
- 让用户在保存前就得到明确的格式错误提示
- 保证编辑已有配置时能稳定往返（load -> edit -> save）
- 不修改后端 `mcp-servers.json` 的数据结构

**Non-Goals:**
- 不做 shell 风格命令行解析
- 不支持空格分隔或逗号分隔的自动猜测
- 不改动 MCP Hub 后端 API

## Decisions

### 1. `args` 改为 JSON 数组输入

**选择**：前端要求用户输入合法 JSON 数组，而不是自由文本。

示例：

```json
["-y", "@modelcontextprotocol/server-filesystem", "/path/to/dir"]
```

**理由**：
- 与最终持久化格式完全一致
- 没有空格转义、引号嵌套、平台差异等歧义
- 前端可以直接 `JSON.parse` 校验并给出清晰报错

### 2. 输入控件使用 `textarea`

`args`、`env`、`headers` 都使用 `textarea` 承载 JSON 文本，便于多行编辑和格式化回显。

### 3. 保存时严格校验

保存 `stdio` server 时：

- 若 `args` 非空，先 `JSON.parse(argsStr)`
- parse 失败则直接提示错误并中止保存
- parse 成功但结果不是数组，也直接提示错误并中止保存

### 4. 编辑时格式化回显

编辑已有 server 时，`args` 使用 `JSON.stringify(serverConfig.args, null, 2)` 回填，保证二次编辑时结构稳定。

## Risks / Trade-offs

- **学习成本略高**：用户需要输入 JSON，而不是“看起来更随手”的命令行文本  
  这是有意的权衡，用更严格的输入换取确定性。

- **与旧 proposal 候选方案不同**：最终没有选择空格拆分  
  这是合理偏离，因为代码已经证明 JSON 数组方案更稳。
