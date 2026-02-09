# MCP Guardrails

**双层防护的 MCP (Model Context Protocol) 安全网关**

为 AI Agent 与 MCP Server 之间的通信提供企业级安全防护，防止 Prompt Injection、数据泄露、恶意工具调用等攻击。

## 架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              宿主机                                      │
│  ┌─────────┐      ┌──────────────────────────────────────────────────┐  │
│  │  Agent  │─────▶│                  MCP Hub                         │  │
│  │ (Cursor/│      │  ┌────────┐    ┌─────────────────────────────┐   │  │
│  │  Claude │      │  │  WAF1  │───▶│  MCP Server (rest-api等)    │   │  │
│  │  Code)  │      │  │ 静态规则│    │  通过 npx/node 启动         │   │  │
│  └─────────┘      │  └────────┘    └──────────────┬──────────────┘   │  │
│                   └───────────────────────────────┼──────────────────┘  │
└───────────────────────────────────────────────────┼─────────────────────┘
                                                    │ HTTP
┌───────────────────────────────────────────────────┼─────────────────────┐
│                            Docker                 ▼                     │
│  ┌──────────────────────┐      ┌──────────────────────────────────┐    │
│  │        WAF2          │─────▶│         目标应用                  │    │
│  │   LLM 语义分析       │      │    (Juice Shop / DVWA 等)        │    │
│  │   :8081              │      │         :3000                    │    │
│  └──────────────────────┘      └──────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 请求流程

```
Agent 请求 → MCP Hub → WAF1 检测 → MCP Server → HTTP 请求 → WAF2 检测 → 目标应用
                ↓              ↓                      ↓
            拦截恶意       拦截注入攻击           拦截语义攻击
            工具调用       (SQL/XSS/命令)         (LLM 分析)
```

## 双层 WAF 架构

| 层级 | 位置 | 检测方式 | 检测内容 |
|------|------|----------|----------|
| **WAF1** | MCP Hub (宿主机) | 静态正则规则 | MCP 协议层攻击 |
| **WAF2** | Docker 代理 | LLM 动态语义分析 | HTTP 流量攻击 |

### WAF1 - MCP 协议层防火墙

在 MCP 工具调用层拦截攻击，检测规则包括：

- **SQL 注入** - `UNION SELECT`、`DROP TABLE`、`' OR 1=1` 等
- **命令注入** - `; rm -rf`、`| cat /etc/passwd`、`$(command)` 等
- **XSS 攻击** - `<script>`、`javascript:`、`onerror=` 等
- **路径遍历** - `../../../etc/passwd`、`....//....//` 等
- **敏感文件访问** - `/etc/passwd`、`.env`、`id_rsa` 等
- **密钥泄露** - API Key、Token、私钥模式检测
- **PII 数据** - 身份证号、手机号、银行卡号

### WAF2 - HTTP 流量层防火墙

使用 LLM (大语言模型) 进行语义级别的攻击检测：

- **请求语义分析** - 理解攻击意图，识别变形攻击
- **响应数据检测** - 检测敏感信息泄露
- **OWASP 分类** - 标准化攻击类型分类
- **MITRE ATT&CK** - 战术技术映射

## 快速开始

### 前置要求

- Docker & Docker Compose
- Node.js >= 18
- npm

### 一键启动

```bash
# Linux / macOS
chmod +x start.sh
./start.sh

# Windows
start.bat
```

启动脚本会自动：
1. 启动 Docker 服务 (WAF2 + Juice Shop 靶机)
2. 安装 MCP Hub 依赖
3. 启动 MCP Hub (前台运行)

### 手动启动

```bash
# 步骤 1: 启动 Docker 服务
docker-compose -f docker-compose.yml -f targets/juice-shop.yml up -d

# 步骤 2: 启动 MCP Hub
cd mcp-hub
npm install
node ./src/utils/cli.js --port 4000 --config ../config/mcp-servers.json
```

### 访问服务

| 服务 | 地址 | 说明 |
|------|------|------|
| Dashboard | http://localhost:4000 | 安全仪表盘 & 管理界面 |
| MCP Endpoint | http://localhost:4000/mcp | Agent 连接入口 |
| WAF2 代理 | http://localhost:8081 | HTTP 流量代理入口 |
| Juice Shop | http://localhost:3000 | 测试靶机 (直接访问) |

**Dashboard 登录凭据：** `admin` / `guardrails`

## 配置

### 配置 MCP Server

编辑 `config/mcp-servers.json`：

```json
{
  "mcpServers": {
    "rest-api": {
      "displayName": "REST API Tester",
      "command": "npx",
      "args": ["-y", "dkmaker-mcp-rest-api"],
      "env": {
        "REST_BASE_URL": "http://localhost:8081"
      }
    }
  }
}
```

> **关键配置：** `REST_BASE_URL` 必须指向 WAF2 代理 (`http://localhost:8081`)，这样所有 HTTP 请求都会经过 WAF2 检测。

### 配置 Agent 连接

在你的 AI Agent (Cursor / Claude Code / 其他 MCP 客户端) 中添加：

```json
{
  "mcpServers": {
    "guardrails": {
      "url": "http://localhost:4000/mcp"
    }
  }
}
```

### 切换目标靶机

项目内置多个测试靶机：

```bash
# Juice Shop (默认)
docker-compose -f docker-compose.yml -f targets/juice-shop.yml up -d

# DVWA (登录: admin / password)
docker-compose -f docker-compose.yml -f targets/dvwa.yml up -d

# WebGoat
docker-compose -f docker-compose.yml -f targets/webgoat.yml up -d
```

### 配置 WAF2 LLM

编辑 `.env` 文件配置 LLM API：

```bash
# 通义千问 API
QWEN_API_KEY=sk-your-api-key
LLM_MODEL=qwen-turbo

# 目标应用 URL (Docker 内部访问)
TARGET_URL=http://host.docker.internal:3000
```

## 测试攻击拦截

### 通过 curl 测试

```bash
# 先登录获取 session
curl -c cookies.txt -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"guardrails"}'

# SQL 注入测试 (应被 WAF1 拦截)
curl -b cookies.txt -X POST http://localhost:4000/api/servers/tools \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "rest-api",
    "tool": "test_request",
    "arguments": {
      "method": "GET",
      "endpoint": "/api?id=1 UNION SELECT * FROM users--"
    }
  }'

# 命令注入测试 (应被 WAF1 拦截)
curl -b cookies.txt -X POST http://localhost:4000/api/servers/tools \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "rest-api",
    "tool": "test_request",
    "arguments": {
      "method": "GET",
      "endpoint": "/api?cmd=; rm -rf /"
    }
  }'

# 正常请求测试 (应该通过)
curl -b cookies.txt -X POST http://localhost:4000/api/servers/tools \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "rest-api",
    "tool": "test_request",
    "arguments": {
      "method": "GET",
      "endpoint": "/api/Products/1"
    }
  }'
```

### 预期拦截响应

```json
{
  "error": "WAF1 拦截",
  "allowed": false,
  "reason": "检测到 sqlInjection: /union\\s+select/i",
  "type": "RULE_BLOCKED",
  "category": "sqlInjection"
}
```

## 项目结构

```
mcp-guardrails/
├── mcp-hub/                    # MCP Hub + WAF1 (宿主机运行)
│   ├── src/
│   │   ├── waf1/               # WAF1 静态规则检测模块
│   │   │   ├── index.js        # WAF1 主入口
│   │   │   └── rules.js        # 检测规则定义
│   │   ├── dashboard/          # 前端仪表盘 (HTML/CSS/JS)
│   │   ├── utils/
│   │   │   ├── cli.js          # 命令行启动入口
│   │   │   ├── auth.js         # 认证模块
│   │   │   └── logger.js       # 日志模块
│   │   ├── server.js           # HTTP 服务器
│   │   └── MCPHub.js           # MCP Hub 核心
│   └── package.json
│
├── waf2/                       # WAF2 LLM 代理 (Docker 运行)
│   ├── waf2_proxy.py           # 代理服务器
│   ├── llm_analyzer.py         # LLM 分析模块
│   └── Dockerfile
│
├── config/
│   ├── mcp-servers.json        # MCP Server 配置
│   └── guardrails-config.json  # WAF 配置
│
├── targets/                    # 内置靶机 Docker Compose 配置
│   ├── juice-shop.yml          # OWASP Juice Shop
│   ├── dvwa.yml                # Damn Vulnerable Web App
│   └── webgoat.yml             # OWASP WebGoat
│
├── docker-compose.yml          # Docker 基础配置 (WAF2)
├── start.sh                    # Linux/macOS 一键启动
├── start.bat                   # Windows 一键启动
├── .env.example                # 环境变量模板
└── README.md
```

## API 参考

### 认证

| 端点 | 方法 | 说明 |
|------|------|------|
| `/auth/login` | POST | 登录 |
| `/auth/logout` | POST | 登出 |
| `/auth/status` | GET | 检查登录状态 |

### MCP 管理

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/servers` | GET | 获取所有 MCP Server 状态 |
| `/api/servers/tools` | POST | 执行 MCP 工具 |
| `/api/servers/resources` | POST | 访问 MCP 资源 |
| `/api/health` | GET | 健康检查 |

### MCP 客户端连接

| 端点 | 说明 |
|------|------|
| `/mcp` | MCP 协议端点 (供 Agent 连接) |

## 常见问题

### Q: WAF2 无法连接目标应用？

确保 Docker 网络配置正确，WAF2 通过 `host.docker.internal` 访问宿主机上的服务。

### Q: 如何添加自定义 MCP Server？

编辑 `config/mcp-servers.json`，添加新的服务器配置。支持任何 stdio 模式的 MCP Server。

### Q: 如何禁用 WAF1/WAF2？

编辑 `config/guardrails-config.json`，将 `waf1.enabled` 或 `waf2.enabled` 设为 `false`。

### Q: 如何代理到自己的应用？

1. 修改 `.env` 中的 `TARGET_URL` 指向你的应用
2. 或直接修改 `config/mcp-servers.json` 中的 `REST_BASE_URL`

## 许可证

MIT License
