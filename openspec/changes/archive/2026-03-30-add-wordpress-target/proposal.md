## Why

现有 demo 目标应用（DVWA、Juice Shop、WebGoat）是通用的 CTF 靶场，无法体现 MCP 协议层的安全价值。WordPress 占全球 43% 网站份额，其官方 MCP Adapter（WordPress/mcp-adapter）通过 Abilities API 让 AI Agent 直接操作站点内容，产生真实可信的 MCP tool call 攻击面。用 WordPress 作为目标应用，一次 demo 可展示 5+ 种 WAF1 检测能力（XSS、SQLi、SSRF、路径遍历、Prompt 注入、凭证泄露），比现有靶场更贴合"MCP 安全"的叙事。

## What Changes

- 新增 `targets/wordpress.yml` — WordPress 6.9+ 与 MySQL Docker 部署，端口映射 3000:80，与现有 targets 模式一致
- 新增 WordPress MCP Server 配置 — 使用官方 `wordpress/mcp-adapter` 插件，通过 STDIO（wp-cli）连接 MCP Hub
- 更新 `config/mcp-servers.json` — 添加 WordPress MCP Server 定义
- 新增 demo 攻击场景文档 — 6 个攻击场景的具体 prompt，可在 Dashboard 演示

## Capabilities

### New Capabilities

- `wordpress-target`: WordPress 作为 MCP 目标应用的 Docker 部署与 MCP Adapter 集成配置

### Modified Capabilities

（无需修改现有 spec — WAF1 规则已覆盖所需攻击检测类型，不需要代码变更）

## Impact

- **Docker**: 新增 `targets/wordpress.yml`（WordPress + MySQL 两个容器），可选性加载，不影响现有 compose
- **MCP Hub**: `config/mcp-servers.json` 增加一个 server 定义，MCP Hub 无需代码改动
- **WAF1**: 不需要改代码，现有 10 类正则规则 + 5 种检测器已覆盖全部攻击场景
- **WAF2**: 本方案使用官方插件（PHP 内部执行），WAF2 不参与 WordPress 流量，无影响
- **Dashboard**: 无改动，新增的 WordPress MCP Server 自动出现在 MCP Servers tab
- **依赖**: WordPress 6.9+（自带 Abilities API）、wp-cli、composer（容器内安装）
