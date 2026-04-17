## Context

项目当前有三个 Docker 化的目标应用（DVWA、Juice Shop、WebGoat），都是通用 CTF 靶场。WordPress 作为全球 43% 网站使用的 CMS，其官方 MCP Adapter（`wordpress/mcp-adapter`）通过 Abilities API 暴露站点操作给 AI Agent，是更贴合项目 "MCP 安全" 叙事的目标应用。

官方 mcp-adapter 使用 STDIO 传输（通过 wp-cli），tool call 在 WordPress PHP 内部执行。这意味着只有 WAF1（MCP 协议层）参与拦截，WAF2 不会看到 WordPress 流量。

## Goals / Non-Goals

**Goals:**
- WordPress 6.9+（自带 Abilities API）+ MySQL 的 Docker 一键部署
- 安装配置 `wordpress/mcp-adapter`，注册 demo 用 abilities
- MCP Hub 通过 STDIO（wp-cli）连接 WordPress MCP Server
- 在 Dashboard 上能演示 5+ 种 WAF1 拦截场景

**Non-Goals:**
- 不做 WAF2 与 WordPress 的集成（官方插件走 PHP 内部调用，无 HTTP 流量）
- 不做 WordPress 管理界面的安全加固
- 不做 WordPress 插件/主题市场相关功能
- 不做生产级部署（无持久化卷、无备份）

## Decisions

### D1: WordPress Docker 镜像选择

**选择**: `wordpress:6.9-php8.2-apache`

**理由**: WordPress 6.9 是第一个内置 Abilities API 的版本，mcp-adapter 依赖它。PHP 8.2 是 mcp-adapter 的最低要求。Apache 变体比 FPM 简单，不需要单独配 nginx。

**备选**: `wordpress:latest` — 风险是 latest 可能回退到不含 Abilities API 的版本。

### D2: MCP Adapter 安装方式

**选择**: Docker entrypoint 脚本自动安装

在 WordPress 容器启动后，通过自定义 entrypoint 脚本执行：
1. 等待 WordPress 初始化完成
2. `wp plugin install wordpress-mcp --activate`（或 composer require）
3. 注册 demo abilities（create-post、search-posts、list-users 等）

**理由**: 比构建自定义镜像更灵活，也比手动安装更可复现。

**备选**: 构建包含 mcp-adapter 的自定义 WordPress 镜像 — 更稳定但维护成本高。

### D3: Abilities 注册方式

**选择**: 自定义 WordPress 插件（mu-plugin）

在 `wp-content/mu-plugins/` 放置一个 PHP 文件，通过 `wp_register_ability()` 注册以下 abilities：

| Ability Name | 操作 | 可触发的 WAF1 规则 |
|---|---|---|
| `demo/create-post` | 创建文章 | XSS（title/content）、Prompt Injection |
| `demo/search-posts` | 搜索文章 | SQL Injection（search query）|
| `demo/list-users` | 列出用户 | Sensitive Data（用户信息）|
| `demo/upload-media` | 上传媒体 | SSRF（URL 参数）|
| `demo/read-file` | 读取文件 | Path Traversal、Sensitive Files |
| `demo/get-settings` | 读取设置 | Secrets（API key 泄露）|

**理由**: mu-plugins 自动激活，不需要手动启用。每个 ability 精确覆盖一种攻击面。

### D4: MCP Hub 连接方式

**选择**: STDIO via wp-cli（在 Docker 容器内）

`config/mcp-servers.json` 配置：
```json
{
  "wordpress": {
    "command": "docker",
    "args": ["exec", "-i", "wordpress", "wp", "--allow-root",
             "mcp-adapter", "serve", "--server=mcp-adapter-default-server", "--user=admin"]
  }
}
```

**理由**: MCP Hub 已经支持 STDIO 传输，`docker exec -i` 可以把容器内的 wp-cli stdio 暴露出来。不需要额外的 HTTP transport 配置。

**备选**: HTTP transport + Application Passwords — 更复杂，需要处理认证 token，且 MCP Hub 对 HTTP MCP transport 的支持需要验证。

### D5: Docker Compose 集成

**选择**: 独立的 `targets/wordpress.yml`，通过 `-f` 叠加使用

```bash
docker-compose -f docker-compose.yml -f targets/wordpress.yml up -d
```

与现有 DVWA/JuiceShop/WebGoat 的模式完全一致。WordPress 容器名 `wordpress`，MySQL 容器名 `wordpress-db`，都加入 `mcp-net` 网络。

## Risks / Trade-offs

**[WordPress 6.9 镜像可用性]** → WordPress 6.9 于 2026 年发布，Docker Hub 上的 tag 可能命名不同。**缓解**: 启动脚本检查 WordPress 版本，如果 < 6.9 则打印错误提示。

**[mcp-adapter 安装失败]** → Composer 依赖可能因网络问题失败。**缓解**: 在 Dockerfile/entrypoint 中加重试逻辑；提供离线安装包作为 fallback。

**[wp-cli STDIO 在 docker exec 中的稳定性]** → `docker exec -i` 的 stdin/stdout 管道可能不稳定。**缓解**: 先做 PoC 验证，如果不稳定则切换到 HTTP transport。

**[Abilities API 变更]** → WordPress 6.9 的 Abilities API 仍然较新，API 可能变化。**缓解**: 固定 mcp-adapter 版本号。
