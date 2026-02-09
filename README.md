# MCP Guardrails

**双层防护的 MCP (Model Context Protocol) 安全网关**

为 AI Agent 与 MCP Server 之间的通信提供企业级安全防护，防止 Prompt Injection、数据泄露、恶意工具调用等攻击。

## 架构图

```
┌─────────┐     ┌─────────────────── 宿主机 ───────────────────┐
│  Agent  │────▶│  MCP Hub (WAF1)  ────▶  MCP Server (stdio)  │
│ (Cursor)│     └────────────────────────────┬────────────────┘
└─────────┘                                  │ HTTP
                ┌─────────────── Docker ─────┼────────────────┐
                │                            ▼                │
                │  WAF2 (:8081)  ────▶  目标应用 (:3000)      │
                └─────────────────────────────────────────────┘
```

## 特性

### 双层 WAF 架构

| 层级 | 名称 | 检测方式 | 位置 |
|------|------|----------|------|
| **WAF1** | MCP 协议层防火墙 | 静态正则规则 | MCP Hub (宿主机) |
| **WAF2** | HTTP 流量层防火墙 | LLM 动态语义分析 | Docker 代理 |

### WAF1 - 静态规则检测

- **SQL 注入检测** - UNION、SELECT、DROP 等 SQL 关键字
- **命令注入检测** - Shell 命令如 `; rm -rf`、`| cat` 等
- **XSS 跨站脚本** - `<script>`、`javascript:` 等
- **路径遍历检测** - `../` 目录遍历 payload
- **敏感文件访问** - `/etc/passwd`、`.env` 等
- **密钥泄露检测** - API Key、Token、私钥
- **PII 检测** - 身份证、手机号、银行卡

### WAF2 - LLM 动态检测

- **请求语义分析** - AI 理解攻击意图
- **响应数据泄露检测** - 检测敏感信息外泄
- **OWASP 标准分类** - 攻击类型标准化
- **MITRE ATT&CK 映射** - 战术技术对应

## 快速开始

### 前置要求

- Docker & Docker Compose
- Node.js >= 18

### 一键启动 (推荐)

```bash
# Windows
start.bat

# Linux / macOS
./start.sh
```

这会自动：
1. 启动 Docker 服务 (WAF2 + Juice Shop 靶机)
2. 安装 MCP Hub 依赖
3. 启动 MCP Hub

### 手动启动

```bash
# 步骤 1: 启动 Docker 服务
docker-compose -f docker-compose.yml -f targets/juice-shop.yml up -d

# 步骤 2: 启动 MCP Hub
cd mcp-hub
npm install
npm start
```

### 访问服务

| 服务 | 地址 | 说明 |
|------|------|------|
| Dashboard | http://localhost:4000 | 安全仪表盘 |
| MCP Hub | http://localhost:4000/mcp | Agent 连接入口 |
| WAF2 | http://localhost:8081 | HTTP 代理入口 |
| Juice Shop | http://localhost:3000 | 测试靶机 |

**Dashboard 登录：** 默认账号 `admin` / `guardrails`

## 配置 MCP Server

编辑 `config/mcp-servers.json` 添加你的 MCP Server：

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

**重要：** 将 `REST_BASE_URL` 设为 `http://localhost:8081`（WAF2 代理），这样 HTTP 请求会经过 WAF2 检测。

## 配置 Agent

在你的 Agent (Cursor/Claude Code) 中配置连接到 MCP Hub：

```json
{
  "mcpServers": {
    "guardrails": {
      "url": "http://localhost:4000/mcp"
    }
  }
}
```

## 测试攻击拦截

```bash
# SQL 注入测试 (应被 WAF1 拦截)
curl -X POST http://localhost:4000/api/servers/tools \
  -H "Content-Type: application/json" \
  -d '{"server_name":"rest-api","tool":"test_request","arguments":{"endpoint":"/api?id=1 UNION SELECT * FROM users--"}}'
```

## 项目结构

```
mcp-guardrails/
├── mcp-hub/                 # MCP Hub + WAF1 (宿主机运行)
│   ├── src/
│   │   ├── waf1/            # WAF1 检测模块
│   │   ├── dashboard/       # 前端仪表盘
│   │   └── ...
│   └── package.json
├── waf2/                    # WAF2 LLM 代理 (Docker)
├── config/                  # 配置文件
│   └── mcp-servers.json     # MCP Server 配置
├── targets/                 # 内置靶机配置
├── docker-compose.yml
├── start.sh                 # Linux/macOS 启动脚本
├── start.bat                # Windows 启动脚本
└── README.md
```

## 许可证

MIT License
