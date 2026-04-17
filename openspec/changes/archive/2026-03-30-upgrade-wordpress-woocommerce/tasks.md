## 1. WooCommerce 安装 (setup.sh)

- [x] 1.1 更新 `targets/wordpress/setup.sh` — 追加 WooCommerce 安装逻辑
- [x] 1.2 更新 `targets/wordpress/setup.sh` — 追加 sample data 导入 (PHP eval-file 方式)
- [x] 1.3 更新 `targets/wordpress/setup.sh` — 追加 wc-mcp-ability 插件安装

## 2. Demo Abilities 精简

- [x] 2.1 修改 `targets/wordpress/mu-plugins/mcp-demo-abilities.php` — 移除 `demo/create-post` 和 `demo/search-posts`
- [x] 2.2 验证保留的 4 个 abilities 仍正常注册

## 3. WooCommerce HTTP MCP 接入

- [x] 3.1 在 mu-plugin 中添加 `woocommerce_mcp_allow_insecure_transport` filter 允许 HTTP 本地开发
- [x] 3.2 在 `targets/wordpress/setup.sh` 中自动创建 WooCommerce REST API Key 并输出
- [x] 3.3 在 `config/mcp-servers.json` 中添加 `woocommerce` server 配置 (url + headers X-MCP-API-Key)
- [x] 3.4 设置 WordPress permalink 结构为 `/%postname%/` (REST API 需要)

## 4. 端到端验证

- [x] 4.1 重启容器，确认 setup.sh 自动完成所有安装（WooCommerce + sample data + API Key）
- [x] 4.2 STDIO 验证：mcp-adapter-default-server 暴露 4 个 demo abilities
- [x] 4.3 HTTP 验证：WooCommerce MCP Server 暴露 9 个工具 (products + orders CRUD)
- [x] 4.4 重启 MCP Hub，确认两个 server 都连接成功 (wordpress=STDIO, woocommerce=HTTP)
