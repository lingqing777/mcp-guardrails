# MCP Guardrails

**双层防护的 MCP (Model Context Protocol) 安全网关**

为 AI Agent 与 MCP Server 之间的通信提供企业级安全防护，防止 Prompt Injection、数据泄露、恶意工具调用等攻击。

## 特性

### 双层 WAF 架构

| 层级 | 名称 | 检测方式 | 位置 |
|------|------|----------|------|
| **WAF1** | MCP 协议层防火墙 | 静态正则规则 | MCP Hub 中间件 |
| **WAF2** | HTTP 流量层防火墙 | LLM 动态语义分析 | 反向代理 |

### WAF1 - 静态规则检测

- **SQL 注入检测** - UNION、SELECT、DROP 等 SQL 关键字
- **命令注入检测** - Shell 命令如 `; rm -rf`、`| cat` 等
- **XSS 跨站脚本** - `<script>`、`javascript:` 等
- **路径遍历检测** - `../` 目录遍历 payload
- **敏感文件访问** - `/etc/passwd`、`.env` 等
- **密钥泄露检测** - API Key、Token、私钥
- **PII 检测** - 身份证、手机号、银行卡
- **Unicode 异常** - 零宽字符、控制字符

### WAF2 - LLM 动态检测

- **请求语义分析** - AI 理解攻击意图
- **响应数据泄露检测** - 检测敏感信息外泄
- **OWASP 标准分类** - 攻击类型标准化
- **MITRE ATT&CK 映射** - 战术技术对应
- **智能缓存** - 减少重复 LLM 调用

## 架构图

```
┌─────────────┐      ┌─────────────────────────────────────────┐      ┌─────────────┐
│             │      │              MCP Hub                    │      │             │
│   AI Agent  │────▶│  ┌───────┐     ┌───────────┐            │────▶│  MCP Server │
│   (Claude)  │      │  │ WAF1  │───▶│ MCP Router│            │      │  (Tools)    │
│             │      │  └───────┘     └───────────┘            │      │             │
└─────────────┘      └─────────────────────────────────────────┘      └──────┬──────┘
                                                                             │
                                                                             ▼
                                                      ┌─────────────────────────────────────────┐      ┌─────────────┐
                                                      │              WAF2 Proxy                 │      │             │
                                                      │  ┌─────────┐     ┌──────────┐           │────▶│  Target App │
                                                      │  │ LLM     │───▶│ Upstream │           │      │  (web)      │
                                                      │  │ Analysis│     │ Forward  │           │      │             │
                                                      │  └─────────┘     └──────────┘           │      └─────────────┘
                                                      └─────────────────────────────────────────┘
```

## 快速开始

### 前置要求

- Docker & Docker Compose

### 使用场景

项目支持两种使用场景：

| 场景 | 说明 | 适用情况 |
|------|------|----------|
| **场景A** | 代理到你自己的应用 | 本机/内网/外网应用均可 |
| **场景B** | 使用内置靶机 | 快速体验、安全测试 |

### 场景A：代理到你自己的应用

```bash
# 1. 克隆项目
git clone https://github.com/lingqing777/mcp-guardrails.git
cd mcp-guardrails

# 2. 配置目标 URL
cp .env.example .env
# 编辑 .env，设置 TARGET_URL 为你的应用地址：
#   - 本机应用:  http://host.docker.internal:8080
#   - 内网应用:  http://192.168.1.100:8080
#   - 外网应用:  https://example.com

# 3. 启动
docker-compose up -d

# 4. 访问 Dashboard
open http://localhost:4000
```

### 场景B：使用内置靶机

```bash
# OWASP Juice Shop
docker-compose -f docker-compose.yml -f targets/juice-shop.yml up -d

# 或 DVWA
docker-compose -f docker-compose.yml -f targets/dvwa.yml up -d

# 或 WebGoat
docker-compose -f docker-compose.yml -f targets/webgoat.yml up -d
```

### 访问服务

| 服务 | 地址 | 说明 |
|------|------|------|
| Dashboard | http://localhost:4000 | 安全仪表盘 |
| MCP Hub | http://localhost:4000/mcp | Agent 连接入口 |
| WAF2 | http://localhost:8081 | HTTP 代理入口 |

**Dashboard 登录：** 默认账号 `admin` / `guardrails`，可通过环境变量 `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` 覆盖。

## Dashboard 功能

### 总览页面
- 实时请求统计
- 拦截率与趋势
- 攻击类型分布
- 严重等级分布

### MCP Servers 管理
- Server 连接状态
- 可用工具列表
- 工具测试面板

### 配置面板
- 防护模式切换 (完整/轻量)
- WAF1 规则开关
- WAF2 LLM 配置
- 数据导出管理

## API 参考

### WAF1 统计 API

```bash
# 获取仪表盘数据
GET http://localhost:4000/api/waf1/dashboard

# 重置统计
POST http://localhost:4000/api/waf1/reset
```

### WAF2 统计 API

```bash
# 获取仪表盘数据
GET http://localhost:8081/waf2/dashboard

# 健康检查
GET http://localhost:8081/waf2/health
```

## 测试攻击拦截

### SQL 注入测试

```bash
curl -X POST http://localhost:4000/api/servers/tools \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "rest-api",
    "tool": "test_request",
    "arguments": {
      "method": "GET",
      "endpoint": "/api/users?id=1 UNION SELECT * FROM users--"
    }
  }'
```

预期响应：
```json
{
  "blocked": true,
  "reason": "检测到 SQL 注入攻击",
  "category": "sqlInjection",
  "severity": "high"
}
```

### 命令注入测试

```bash
curl -X POST http://localhost:4000/api/servers/tools \
  -H "Content-Type: application/json" \
  -d '{
    "server_name": "rest-api",
    "tool": "test_request",
    "arguments": {
      "method": "POST",
      "endpoint": "/api/exec",
      "body": {"cmd": "; rm -rf /"}
    }
  }'
```

## 项目结构

```
mcp-guardrails/
├── mcp-hub/                 # MCP Hub + WAF1
│   ├── src/
│   │   ├── server.js        # Express 主入口
│   │   ├── api/             # API 路由模块
│   │   ├── waf1/            # WAF1 检测模块
│   │   ├── mcp/             # MCP 协议实现
│   │   ├── services/        # 核心服务
│   │   ├── utils/           # 工具模块 (认证、日志等)
│   │   └── dashboard/       # 前端仪表盘
│   └── package.json
├── waf2/                    # WAF2 LLM 代理
│   ├── waf2_proxy.py        # FastAPI 代理服务
│   └── requirements.txt
├── config/                  # 配置文件
│   ├── guardrails-config.json
│   └── mcp-servers.json
├── targets/                 # 内置靶机配置
│   ├── juice-shop.yml
│   ├── dvwa.yml
│   └── webgoat.yml
├── docker-compose.yml
├── .env.example
└── README.md
```

## 技术参考

- [MCP Protocol](https://modelcontextprotocol.io/) - Model Context Protocol 规范
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web 安全风险
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - LLM 安全风险
- [MITRE ATT&CK](https://attack.mitre.org/) - 攻击战术技术库

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License
