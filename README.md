# MCP Guardrails

**双层防护的 MCP (Model Context Protocol) 安全网关**

为 AI Agent 与 MCP Server 之间的通信提供企业级安全防护，防止 Prompt Injection、数据泄露、恶意工具调用等攻击。

![Architecture](docs/architecture.png)

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

- Node.js >= 18
- Python >= 3.9
- Docker & Docker Compose (可选)

### 1. 克隆项目

```bash
git clone https://github.com/lingqing777/mcp-guardrails.git
cd mcp-guardrails
```

### 2. 安装依赖

```bash
# MCP Hub
cd mcp-hub
npm install

# WAF2
cd ../waf2
pip install -r requirements.txt
```

### 3. 配置

复制示例配置文件：

```bash
cp config.example.json config.json
```

编辑 `config.json`：

```json
{
  "mcpServers": {
    "rest-api": {
      "command": "node",
      "args": ["path/to/mcp-server/build/index.js"],
      "env": {
        "REST_BASE_URL": "http://localhost:8081"
      }
    }
  },
  "waf1": {
    "enabled": true,
    "mode": "block",
    "rules": {
      "sqlInjection": {"enabled": true, "severity": "high"},
      "commandInjection": {"enabled": true, "severity": "critical"},
      "xss": {"enabled": true, "severity": "high"}
    }
  },
  "waf2": {
    "enabled": true,
    "upstream": "http://localhost:3000",
    "llm": {
      "provider": "qwen",
      "model": "qwen-turbo",
      "apiKey": "${QWEN_API_KEY}"
    }
  }
}
```

### 4. 启动服务

**方式一：手动启动**

```bash
# 终端 1 - MCP Hub (WAF1)
cd mcp-hub
node src/utils/cli.js --port 4000 --config ../config.json

# 终端 2 - WAF2 Proxy
cd waf2
export QWEN_API_KEY="your-api-key"
python waf2_proxy.py

# 终端 3 - 目标应用 (示例: Juice Shop)
docker run -p 3000:3000 bkimminich/juice-shop
```

**方式二：Docker Compose**

```bash
docker-compose up -d
```

### 5. 访问仪表盘

打开浏览器访问：`http://localhost:8888/dashboard.html`

登录默认密码admin/guardrails

可通过环境变量DASHBOARD_USERNAME/DASHBOARD_PASSWORD覆盖

## 仪表盘功能

### 总览页面
- 实时请求统计
- 拦截率与趋势
- 攻击类型分布
- 严重等级分布

### MCP Servers 管理
- Server 连接状态
- 可用工具列表
- 工具测试面板

### 配置面板 (cc-switch 风格)
- WAF1 规则开关
- WAF2 LLM 配置
- API 端点设置
- 数据导出管理

## API 参考

### WAF1 统计 API

```bash
# 获取统计
GET http://localhost:4000/api/waf1/stats

# 获取仪表盘数据
GET http://localhost:4000/api/waf1/dashboard

# 重置统计
POST http://localhost:4000/api/waf1/reset
```

### WAF2 统计 API

```bash
# 获取统计
GET http://localhost:8081/waf2/stats

# 获取仪表盘数据
GET http://localhost:8081/waf2/dashboard

# 健康检查
GET http://localhost:8081/waf2/health
```

### MCP 工具调用 API

```bash
# 调用 MCP 工具 (经过 WAF1 检测)
POST http://localhost:4000/api/servers/tools
Content-Type: application/json

{
  "server_name": "rest-api",
  "tool": "test_request",
  "arguments": {
    "method": "GET",
    "endpoint": "/api/products"
  }
}
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

## Agent 集成示例

参考 `agent/mcp_agent.py`：

```python
from mcp_agent import run_agent

# 运行 Agent，所有工具调用都会经过 WAF1 和 WAF2 检测
run_agent("探测 /rest/user/login 接口的安全性")
```

## 项目结构

```
mcp-guardrails/
├── mcp-hub/                 # MCP Hub + WAF1
│   ├── src/
│   │   ├── server.js        # Express 服务器
│   │   ├── waf1.js          # WAF1 中间件
│   │   ├── MCPHub.js        # MCP 连接管理
│   │   └── utils/
│   └── package.json
├── waf2/                    # WAF2 LLM 代理
│   ├── waf2_proxy.py        # FastAPI 代理服务
│   └── requirements.txt
├── demo/                    # 演示仪表盘
│   └── dashboard.html       # 统一安全仪表盘
├── agent/                   # Agent 示例
│   └── mcp_agent.py         # MCP Agent 实现
├── config.example.json      # 配置示例
├── docker-compose.yml       # Docker 编排
└── README.md
```

## 技术参考

- [MCP Protocol](https://modelcontextprotocol.io/) - Model Context Protocol 规范
- [MCP-Guard Paper](https://arxiv.org/abs/xxx) - MCP 安全研究论文
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web 安全风险
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - LLM 安全风险
- [MITRE ATT&CK](https://attack.mitre.org/) - 攻击战术技术库

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License

## 致谢

- [MCP Hub](https://github.com/anthropics/mcp) - Anthropic MCP 实现
- [Juice Shop](https://github.com/juice-shop/juice-shop) - OWASP 漏洞演练平台
- [cc-switch](https://github.com/farion1231/cc-switch) - UI 设计参考
