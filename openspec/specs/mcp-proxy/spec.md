# MCP Proxy — 协议聚合代理

## Purpose

将多个独立的 MCP Server 聚合为一个统一的 MCP 端点，供 AI Agent 连接。
管理各 MCP Server 的生命周期，处理连接、断开、能力同步和命名空间隔离。

层级：MCP Hub

## Requirements

### 统一端点

- MCP-1: 系统 MUST 在 `http://localhost:4000/mcp` 暴露统一的 MCP 端点
- MCP-2: 统一端点 MUST 聚合所有已连接 MCP Server 的工具、资源和 Prompt
- MCP-3: Agent 只需连接一个端点即可访问所有 MCP Server 的能力

### 命名空间

- MCP-5: 工具名 MUST 使用 `servername__toolname` 格式避免冲突
- MCP-6: 资源和 Prompt 同样 MUST 使用命名空间隔离
- MCP-7: 统一端点 MUST 根据命名空间前缀正确路由调用到对应的 MCP Server

### 传输方式

- MCP-10: 系统 MUST 支持以下 3 种 MCP 传输方式：
  - `stdio` — 子进程方式（默认，通过 command + args 配置）
  - `sse` — Server-Sent Events（通过 url 配置）
  - `http` — 直接 HTTP（通过 url 配置，使用 StreamableHTTPClientTransport）
- MCP-11: 传输方式 MUST 根据 Server 配置自动选择

### Server 配置

- MCP-15: Server 配置 MUST 存储在 `config/mcp-servers.json`
- MCP-16: 配置格式 MUST 支持：
  - stdio: `{ command, args, env }`
  - 远程: `{ url, headers }`
- MCP-17: 配置变更 MUST 触发热重载（自动重连受影响的 Server）

### 连接管理

- MCP-20: 每个 Server MUST 由独立的 MCPConnection 实例管理
- MCP-21: 连接 MUST 有超时机制（防止挂起）
- MCP-22: 连接断开后 MUST 支持手动重连（通过 Dashboard 或 API）
- MCP-23: 多个 Server MUST 并行启动，不互相阻塞

### 多 Server 适配

- MCP-25: 系统 MUST 支持同时连接多个 MCP Server
- MCP-26: 单个 Server 连接失败 MUST NOT 影响其他 Server 的正常运行
- MCP-27: Server 连接失败 MUST 在 Dashboard 显示具体错误信息（不能只显示"离线"）
- MCP-28: 添加配置错误的 Server 时 MUST 返回有意义的错误提示
- MCP-29: Dashboard MUST 展示每个 Server 的独立状态（连接中/在线/离线/错误+详情）

### 能力同步

- MCP-30: 当 MCP Server 的工具/资源/Prompt 发生变更时 MUST 实时同步到统一端点
- MCP-31: 能力变更事件 MUST 通知到所有已连接的 Agent

### API 端点

- MCP-35: MUST 提供 `GET /api/servers` — 列出所有 Server 及状态
- MCP-36: MUST 提供 `GET /api/servers/<id>` — 获取单个 Server 详情
- MCP-37: MUST 提供 `POST /api/servers/<id>/connect` — 手动重连
- MCP-38: MUST 提供 `POST /api/servers/<id>/disconnect` — 断开连接
- MCP-39: MUST 提供 MCP Server CRUD 操作（增删改查配置）

### 请求超时

- MCP-40: 单个工具调用请求超时 MUST 为 5 分钟

## Scenarios

### 多 Server 聚合

```
Given 系统配置了 "filesystem" 和 "rest-api" 两个 MCP Server
And   两者均成功连接
When  Agent 连接到 /mcp 并请求工具列表
Then  Agent 收到所有工具，格式为 filesystem__read_file, filesystem__write_file, rest-api__get, rest-api__post 等
```

### 工具调用路由

```
Given Agent 已连接到统一端点
When  Agent 调用工具 "rest-api__get" 并传递参数
Then  系统根据 "rest-api" 前缀路由到对应的 MCPConnection
And   转发工具调用并返回结果
```

### 单个 Server 故障

```
Given 系统配置了 "filesystem" 和 "rest-api" 两个 Server
And   "rest-api" Server 连接失败
When  Agent 调用 "filesystem__read_file"
Then  调用正常执行并返回结果
And   Dashboard 显示 "rest-api" 状态为错误，并附带具体错误信息
```

### 配置热重载

```
Given 系统运行中
When  用户通过 Dashboard 添加新的 MCP Server 配置
Then  系统自动为新 Server 创建 MCPConnection 并尝试连接
And   已有 Server 连接不受影响
And   Agent 收到能力变更通知
```

### 添加错误配置

```
Given 用户在 Dashboard 添加 MCP Server
When  配置的 command 不存在或 url 不可达
Then  连接尝试超时后标记为错误状态
And   Dashboard 显示具体错误原因（如 "ENOENT: command not found" 或 "ECONNREFUSED"）
And   其他 Server 不受影响
```
