## Why

当前 WordPress 演示站点是空白安装，没有真实内容，作为信安作品赛的 WAF1 拦截演示缺乏说服力。需要将其升级为一个基于 WooCommerce（GitHub 9k+ stars）的真实电商网店，并利用 WooCommerce 10.3+ 原生 MCP 集成，让 AI Agent 通过官方 MCP Adapter 与真实商店数据交互，展示 WAF1 对恶意 tool call 的拦截能力。

## What Changes

- 在 WordPress 容器中安装 WooCommerce 10.6+（最新稳定版），获得产品/订单管理的原生 MCP 能力
- 导入 WooCommerce 官方 sample data（商品、分类、图片），让站点呈现为真实运营网店
- 安装 [wc-mcp-ability](https://github.com/woocommerce/wc-mcp-ability) demo 插件，提供 `store-info` 等额外 MCP 能力
- 更新 `targets/wordpress/setup.sh`，自动化 WooCommerce 安装和数据导入流程
- 评估并清理现有 6 个自定义 demo abilities（`mcp-demo-abilities.php`），保留 WooCommerce 未覆盖的攻击面（路径遍历、SSRF）

## Capabilities

### New Capabilities
- `woocommerce-target`: WooCommerce 电商网店作为 MCP 演示目标的部署和配置，包括自动安装、sample data 导入、MCP 能力注册

### Modified Capabilities
- `waf1`: WAF1 拦截规则需要覆盖 WooCommerce 原生 MCP 能力的攻击面（产品名称 XSS、搜索 SQL 注入、订单数据泄露等）

## Impact

- **Docker 配置**: `targets/wordpress.yml` 无需修改（WooCommerce 安装在已有容器内）
- **setup.sh**: 需追加 WooCommerce 安装、sample data 导入、wc-mcp-ability 插件安装步骤
- **mu-plugins**: `mcp-demo-abilities.php` 需要精简，移除与 WooCommerce 原生能力重叠的部分
- **config/mcp-servers.json**: 无需修改（MCP Adapter 自动暴露新注册的 abilities）
- **WAF1**: 现有规则已覆盖 XSS/SQL 注入/SSRF/路径遍历等攻击类型，无需修改规则引擎
- **Dashboard 5 秒刷新**: 不受影响，WooCommerce 能力通过现有 MCP 通道暴露
- **路由注册顺序**: 不受影响，无新路由
