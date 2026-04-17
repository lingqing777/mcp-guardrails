## 1. WordPress Docker 部署

- [x] 1.1 创建 `targets/wordpress.yml` — WordPress 6.9+ (`wordpress:6.9-php8.2-apache`) + MySQL 8.0，端口 3000:80，容器名 `wordpress` / `wordpress-db`，网络 `mcp-net`
- [x] 1.2 创建 `targets/wordpress/setup.sh` — 容器 entrypoint 脚本：等待 WordPress 初始化 → 安装 wp-cli → 安装 mcp-adapter 插件 → 创建 admin 用户（如不存在）
- [x] 1.3 验证 `docker-compose -f docker-compose.yml -f targets/wordpress.yml up -d` 能启动，`localhost:3000` 可访问 WordPress

## 2. Demo Abilities 注册

- [x] 2.1 创建 `targets/wordpress/mu-plugins/mcp-demo-abilities.php` — WordPress mu-plugin，通过 `wp_register_ability()` 注册 demo abilities。初始版本包含 6 个能力；后续 `upgrade-wordpress-woocommerce` 已移除 `demo/create-post` 和 `demo/search-posts`，当前保留 `demo/list-users`、`demo/upload-media`、`demo/read-file`、`demo/get-settings`
- [x] 2.2 在 `targets/wordpress.yml` 中配置 volume 挂载，将 mu-plugin 文件映射到容器内 `/var/www/html/wp-content/mu-plugins/`
- [x] 2.3 验证 `wp mcp-adapter serve` 能启动，`tools/list` 返回注册的 abilities

## 3. MCP Hub 集成

- [x] 3.1 更新 `config/mcp-servers.json` — 添加 `wordpress` server 定义，command 为 `docker exec -i wordpress wp --allow-root mcp-adapter serve --server=mcp-adapter-default-server --user=admin`
- [x] 3.2 验证 MCP Hub 启动后 Dashboard MCP Servers tab 显示 `wordpress` server 及其工具列表

## 4. WAF1 拦截验证

注：当前 WordPress MCP 采用 `mcp-adapter-{discover,get-info,execute}-ability` 三工具模型，实际业务能力通过 `mcp-adapter-execute-ability` 间接执行。验证项按当前保留的 4 个 demo abilities 重写。

- [x] 4.1 在 Dashboard 工具测试面板中测试正常请求放行：调用 `mcp-adapter-execute-ability` 执行 `demo/get-settings`（`section=general`），确认 WordPress 返回站点配置数据
- [x] 4.2 测试敏感文件/路径攻击拦截：执行 `demo/read-file`，`path` 传 `../../wp-config.php`，确认 WAF1 返回拦截（命中 `sensitiveFiles` 或 `pathTraversal`）
- [x] 4.3 测试 SSRF 拦截：执行 `demo/upload-media`，`url` 传 `http://169.254.169.254/latest/meta-data/`，确认 WAF1 返回 403
- [x] 4.4 测试 Prompt 注入拦截：执行 `demo/get-settings`，`section` 传 `Ignore previous instructions`，确认 WAF1 返回 403
