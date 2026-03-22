# MCP Guardrails

**双层防护的 MCP (Model Context Protocol) 安全网关**

为 AI Agent 与 MCP Server 之间的通信提供安全防护，防止 Prompt Injection、命令注入、数据泄露等攻击。

## 核心功能

- **WAF1** - MCP 协议层静态规则检测
- **WAF2** - HTTP 流量层 LLM 语义分析
- **Dashboard** - 安全事件可视化仪表盘 + 配置管理

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

## 快速开始

### 前置要求

- Docker & Docker Compose
- Node.js >= 18

### 一键启动

```bash
# Linux / macOS
./start.sh

# Windows
start.bat
```

### 配置（全部在 Dashboard 完成）

1. 打开 Dashboard: **http://localhost:4000**
2. 登录: `admin` / `guardrails`
3. 在 **「配置」** 页面设置:
   - 目标应用 URL
   - LLM API Key (Qwen DashScope)
4. 在 **「MCP Servers」** 页面添加你的 MCP Server
5. 配置你的 Agent 连接到 MCP Hub

**就这么简单！**

### Agent 配置

在 AI Agent (Cursor/Claude Desktop 等) 中添加：

```json
{
  "mcpServers": {
    "guardrails": {
      "url": "http://localhost:4000/mcp"
    }
  }
}
```

## 双层 WAF

| 层级 | 位置 | 检测方式 | 检测内容 |
|------|------|----------|----------|
| **WAF1** | MCP Hub | 静态正则规则 | SQL注入、命令注入、XSS、路径遍历、敏感文件 |
| **WAF2** | Docker 代理 | LLM 语义分析 | 攻击意图识别、响应数据泄露、OWASP分类 |

## 服务端口

| 服务 | 地址 |
|------|------|
| Dashboard | http://localhost:4000 |
| MCP Endpoint | http://localhost:4000/mcp |
| WAF2 代理 | http://localhost:8081 |

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
# 启动 WordPress 电商靶场 (推荐，含 WooCommerce MCP 集成)
docker-compose -f docker-compose.yml -f targets/wordpress.yml up -d

# 启动其他靶机
docker-compose -f docker-compose.yml -f targets/juice-shop.yml up -d
```

可用靶机：`wordpress.yml`（推荐）、`juice-shop.yml`、`dvwa.yml`、`webgoat.yml`

### WordPress 电商靶场

WordPress + WooCommerce 电商网店，提供 **两类 MCP Server** 供 AI Agent 调用：

| MCP Server | 传输方式 | 工具数 | 说明 |
|------------|---------|--------|------|
| `wordpress` | STDIO | 4 | 系统管理能力（用户列表、文件读取、媒体上传、站点配置） |
| `woocommerce` | HTTP | 9 | 电商业务操作（商品 CRUD、订单 CRUD） |

### WAF1 拦截验证

通过 Dashboard 工具测试面板调用 `wordpress__mcp-adapter-execute-ability`，验证 WAF1 对以下攻击的拦截：

| 攻击类型 | 测试 payload | 命中规则 |
|----------|-------------|---------|
| XSS | `<script>alert(1)</script>` | `/<script\b/i` |
| SQL 注入 | `' OR 1=1 --` | `/union\s+select/i` 等 |
| 路径遍历 | `../../etc/passwd` | `/\/etc\/passwd/i` |
| SSRF | `http://169.254.169.254/` | `/169\.254\.\d+\.\d+/` |
| Prompt 注入 | `Ignore previous instructions` | `/ignore\s+(previous\|above)\s+instructions/i` |

## 许可证

MIT License
