# MCP Guardrails

**双层防护的 MCP (Model Context Protocol) 安全网关**

为 AI Agent 与 MCP Server 之间的通信提供安全防护，防止 Prompt Injection、命令注入、数据泄露等攻击。

## 核心功能

- **WAF1** - MCP 协议层静态规则检测
- **WAF2** - HTTP 流量层 LLM 语义分析
- **Dashboard** - 安全事件可视化仪表盘

## 架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              宿主机                                      │
│  ┌─────────┐      ┌──────────────────────────────────────────────────┐  │
│  │  Agent  │─────▶│                  MCP Hub                         │  │
│  │         │      │  ┌────────┐    ┌─────────────────────────────┐   │  │
│  │         │      │  │  WAF1  │───▶│  MCP Server (stdio)         │   │  │
│  │         │      │  │ 静态规则│    │                             │   │  │
│  └─────────┘      │  └────────┘    └──────────────┬──────────────┘   │  │
│                   └───────────────────────────────┼──────────────────┘  │
└───────────────────────────────────────────────────┼─────────────────────┘
                                                    │ HTTP
┌───────────────────────────────────────────────────┼─────────────────────┐
│                            Docker                 ▼                     │
│  ┌──────────────────────┐      ┌──────────────────────────────────┐    │
│  │        WAF2          │─────▶│         目标应用                  │    │
│  │   LLM 语义分析       │      │       (你的应用)                 │    │
│  │   :8081              │      │                                  │    │
│  └──────────────────────┘      └──────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

## 双层 WAF

| 层级 | 位置 | 检测方式 | 检测内容 |
|------|------|----------|----------|
| **WAF1** | MCP Hub | 静态正则规则 | SQL注入、命令注入、XSS、路径遍历、敏感文件、密钥泄露、PII |
| **WAF2** | Docker 代理 | LLM 语义分析 | 攻击意图识别、响应数据泄露、OWASP分类、MITRE ATT&CK映射 |

## 快速开始

### 前置要求

- Docker & Docker Compose
- Node.js >= 18

### 配置

1. 复制环境变量文件：
```bash
cp .env.example .env
```

2. 编辑 `.env` 配置：
```bash
# 你要保护的目标应用地址
TARGET_URL=http://your-app:3000

# LLM API 密钥 (用于 WAF2 语义分析)
QWEN_API_KEY=sk-your-api-key
```

3. 配置 MCP Server（编辑 `config/mcp-servers.json`）：
```json
{
  "mcpServers": {
    "your-server": {
      "command": "npx",
      "args": ["-y", "your-mcp-server"],
      "env": {
        "BASE_URL": "http://localhost:8081"
      }
    }
  }
}
```

> **重要：** MCP Server 的 HTTP 请求需指向 WAF2 代理 (`:8081`)，流量会经过安全检测后转发到目标应用。

### 启动

```bash
# Linux / macOS
./start.sh

# Windows
start.bat
```

### 手动启动

```bash
# 1. 启动 WAF2
docker-compose up -d

# 2. 启动 MCP Hub
cd mcp-hub && npm install
node ./src/utils/cli.js --port 4000 --config ../config/mcp-servers.json
```

### 访问

| 服务 | 地址 |
|------|------|
| Dashboard | http://localhost:4000 |
| MCP Endpoint | http://localhost:4000/mcp |
| WAF2 代理 | http://localhost:8081 |

**登录：** `admin` / `guardrails`

### Agent 配置

在你的 AI Agent 中配置连接到 MCP Hub：

```json
{
  "mcpServers": {
    "guardrails": {
      "url": "http://localhost:4000/mcp"
    }
  }
}
```

## 项目结构

```
mcp-guardrails/
├── mcp-hub/              # MCP Hub + WAF1 (宿主机运行)
│   └── src/
│       ├── waf1/         # WAF1 检测模块
│       ├── dashboard/    # 前端仪表盘
│       └── server.js     # HTTP 服务器
├── waf2/                 # WAF2 LLM 代理 (Docker)
├── config/               # 配置文件
├── targets/              # 测试靶机配置 (可选)
├── start.sh              # 启动脚本
└── docker-compose.yml
```

## 测试靶机 (可选)

项目提供测试靶机配置，仅用于开发测试：

```bash
# 启动 WAF2 + 测试靶机
docker-compose -f docker-compose.yml -f targets/juice-shop.yml up -d
```

可用靶机：`juice-shop.yml`、`dvwa.yml`、`webgoat.yml`

## 许可证

MIT License
