# Auth — 认证与会话管理

## Purpose

提供 Dashboard 和 API 端点的登录保护，管理用户账号和会话生命周期。
认证模块是系统的安全边界，划分公开路由与受保护路由。

层级：MCP Hub

## Requirements

### 用户存储

- AUTH-1: 用户凭据 MUST 存储在 `config/users.json`，JSON 文件格式，无数据库依赖
- AUTH-2: 用户数据结构 MUST 包含 `{ username, passwordHash, role, createdAt }`
- AUTH-3: 密码 MUST 使用 bcryptjs 哈希存储，salt rounds = 10
- AUTH-4: 系统 MUST 内置硬编码兜底账号 `admin/guardrails`（可通过环境变量 `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` 覆盖）
- AUTH-5: 兜底账号不存在于 users.json，仅在 users.json 中找不到用户时进行明文比对

### 登录

- AUTH-10: 系统 MUST 提供 `POST /auth/login` 端点接收 `{ username, password }`
- AUTH-11: 登录验证 MUST 先查 users.json（bcrypt 比对），未找到再比对硬编码兜底账号
- AUTH-12: 登录成功 MUST 创建 Session 并通过 Set-Cookie 返回 Session ID
- AUTH-13: 登录成功响应格式 MUST 为 `{ success: true, message, role, expiresAt }`
- AUTH-14: 用户名或密码为空时 MUST 返回 400 `{ success: false, message: "请输入用户名和密码" }`
- AUTH-15: 凭据错误时 MUST 返回 401 `{ success: false, message: "用户名或密码错误" }`

### 注册

- AUTH-20: 系统 MUST 提供 `POST /auth/register` 端点接收 `{ username, password }`
- AUTH-21: 用户名 MUST 匹配 `/^[a-zA-Z0-9_]{3,32}$/`，否则返回 400
- AUTH-22: 密码长度 MUST >= 6，否则返回 400
- AUTH-23: 用户名不得与硬编码默认用户名重复，否则返回 400 `"该用户名已存在"`
- AUTH-24: 用户名不得与 users.json 中已有用户重复，否则返回 400 `"该用户名已存在"`
- AUTH-25: 注册成功 MUST 将新用户追加到 users.json，角色固定为 `viewer`
- AUTH-26: 注册成功响应格式 MUST 为 `{ success: true, message: "注册成功" }`
- AUTH-27: 注册不自动登录，前端注册成功后 1.5s 跳转到 /login

### 登出

- AUTH-30: 系统 MUST 提供 `POST /auth/logout` 端点
- AUTH-31: 登出 MUST 销毁服务端 Session 并清除客户端 Cookie
- AUTH-32: 无论是否携带有效 Session，登出 MUST 返回 200 `{ success: true, message: "已登出" }`

### 状态查询

- AUTH-35: 系统 MUST 提供 `GET /auth/status` 端点
- AUTH-36: 有有效 Session 时返回 `{ authenticated: true, username, role, expiresAt }`
- AUTH-37: 无有效 Session 时返回 `{ authenticated: false }`

### Session 机制

- AUTH-40: Session MUST 存储在内存 Map 中（重启丢失）
- AUTH-41: Session ID MUST 由 `crypto.randomBytes(32).toString('hex')` 生成（64 字符 hex）
- AUTH-42: Session 默认过期时间 MUST 为 24 小时，可通过 `SESSION_EXPIRY_MS` 环境变量覆盖
- AUTH-43: 系统 MUST 每小时清理一次过期 Session
- AUTH-44: Cookie 名称 MUST 为 `mcp_session`
- AUTH-45: Cookie 属性 MUST 为 `httpOnly=true, sameSite=lax`，`secure` 仅在 `NODE_ENV=production` 时启用

### Session 提取

- AUTH-50: Session ID 提取优先级 MUST 为：Cookie → Authorization Bearer → query param `session`

### 认证中间件

- AUTH-55: 受保护路由无有效 Session 且请求为 API/XHR/JSON 时 MUST 返回 401 `{ error: "Unauthorized", message: "请先登录", code: "AUTH_REQUIRED" }`
- AUTH-56: 受保护路由无有效 Session 且请求为普通浏览器访问时 MUST 302 重定向到 `/login`
- AUTH-57: 有有效 Session 时 MUST 将 Session 对象挂载到 `req.session` 并放行

### 页面路由

- AUTH-60: `GET /login` 已登录时 MUST 重定向到 `/`，未登录时返回登录页 HTML
- AUTH-61: `GET /register` 已登录时 MUST 重定向到 `/`，未登录时返回注册页 HTML
- AUTH-62: 登录/注册页 HTML MUST 内联在 auth.js 模板字符串中，非独立 HTML 文件

### 角色

- AUTH-65: 系统 MUST 支持两种角色：`admin`（完整权限）和 `viewer`（受限权限）
- AUTH-66: 硬编码兜底账号角色 MUST 为 `admin`
- AUTH-67: 注册用户角色 MUST 固定为 `viewer`，无 UI 提升途径

### 路由注册顺序

- AUTH-70: 认证路由 MUST 在 server.js 中最先注册（registerAuthRoutes）
- AUTH-71: `app.use('/api', authMiddleware)` MUST 作为认证分界线，其后所有路由需要登录
- AUTH-72: 路由注册顺序变更 MUST 确保不破坏认证边界

## Scenarios

### 登录成功（users.json 用户）

```
Given 用户 "qing" 存在于 users.json 中，密码哈希正确
When  提交 POST /auth/login { username: "qing", password: "正确密码" }
Then  返回 200 { success: true, role: "viewer", expiresAt: <24h后> }
And   Set-Cookie: mcp_session=<64字符hex>; HttpOnly; SameSite=Lax
```

### 登录成功（硬编码兜底）

```
Given users.json 中不存在用户 "admin"
When  提交 POST /auth/login { username: "admin", password: "guardrails" }
Then  返回 200 { success: true, role: "admin", expiresAt: <24h后> }
```

### 登录失败

```
Given 用户 "hacker" 不存在于 users.json 且不匹配硬编码账号
When  提交 POST /auth/login { username: "hacker", password: "wrong" }
Then  返回 401 { success: false, message: "用户名或密码错误" }
```

### 注册成功

```
Given users.json 中不存在用户 "newuser"
When  提交 POST /auth/register { username: "newuser", password: "123456" }
Then  返回 200 { success: true, message: "注册成功" }
And   users.json 新增 { username: "newuser", passwordHash: <bcrypt>, role: "viewer", createdAt: <ISO> }
```

### 注册失败（用户名格式）

```
Given 用户名 "ab" 不匹配 /^[a-zA-Z0-9_]{3,32}$/
When  提交 POST /auth/register { username: "ab", password: "123456" }
Then  返回 400 { success: false, message: "用户名只能包含字母、数字和下划线，长度3-32位" }
```

### 未认证访问 API

```
Given 请求未携带有效 Session
When  访问 GET /api/config (Accept: application/json)
Then  返回 401 { error: "Unauthorized", message: "请先登录", code: "AUTH_REQUIRED" }
```

### 未认证浏览器访问

```
Given 请求未携带有效 Session
When  浏览器访问 GET / (Accept: text/html)
Then  302 重定向到 /login
```

### Session 过期

```
Given Session 创建超过 24 小时
When  使用该 Session 访问任意受保护路由
Then  Session 被销毁，返回 401 或重定向到 /login
```
