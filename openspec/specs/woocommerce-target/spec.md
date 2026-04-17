# woocommerce-target Specification

## Purpose
TBD - created by archiving change upgrade-wordpress-woocommerce. Update Purpose after archive.
## Requirements
### Requirement: WooCommerce 自动安装
setup.sh SHALL 在 WordPress 容器启动后自动安装并激活 WooCommerce 10.6+ 插件。安装前 SHALL 检查 WooCommerce 是否已安装，避免重复安装。

影响层: Docker / targets/wordpress/setup.sh

#### Scenario: 首次启动安装 WooCommerce
- **WHEN** WordPress 容器首次启动且 WooCommerce 未安装
- **THEN** setup.sh 通过 `wp plugin install woocommerce --activate` 安装最新版 WooCommerce

#### Scenario: 容器重建后 WooCommerce 已在卷上
- **WHEN** WordPress 容器重建但 wp_data 卷上 WooCommerce 已存在
- **THEN** setup.sh 检测到已安装，仅确认激活状态，不重复安装

### Requirement: WooCommerce Sample Data 导入
setup.sh SHALL 在 WooCommerce 安装后自动导入官方 sample_products.csv，使站点包含真实商品数据（名称、描述、价格、分类、图片）。

影响层: Docker / targets/wordpress/setup.sh

#### Scenario: 导入 sample data
- **WHEN** WooCommerce 已激活且商品数量为 0
- **THEN** setup.sh 通过 WooCommerce CSV importer 导入 `wp-content/plugins/woocommerce/sample-data/sample_products.csv`，站点包含商品数据

#### Scenario: 已有商品数据时跳过导入
- **WHEN** WooCommerce 已激活且商品数量大于 0
- **THEN** setup.sh 跳过 sample data 导入

### Requirement: wc-mcp-ability 插件安装
setup.sh SHALL 安装并激活 wc-mcp-ability demo 插件（来自 github.com/woocommerce/wc-mcp-ability），提供 `store-info` MCP 能力。

影响层: Docker / targets/wordpress/setup.sh

#### Scenario: 安装 wc-mcp-ability
- **WHEN** WordPress 容器启动且 wc-mcp-ability 未安装
- **THEN** setup.sh 通过 git clone 安装 wc-mcp-ability 到 wp-content/plugins/ 并激活

### Requirement: WooCommerce MCP 能力可发现
WooCommerce 原生 MCP abilities SHALL 通过 MCP Adapter 的 `mcp-adapter-discover-abilities` 工具可发现。MCP 客户端 SHALL 能够通过 `mcp-adapter-execute-ability` 调用 WooCommerce 能力。

影响层: MCP Hub（通过现有 STDIO 通道，无代码修改）

#### Scenario: 发现 WooCommerce 产品管理能力
- **WHEN** MCP 客户端调用 `mcp-adapter-discover-abilities`
- **THEN** 返回的能力列表 SHALL 包含 WooCommerce 产品相关能力（如产品创建、列表、搜索）

#### Scenario: 发现 store-info 能力
- **WHEN** MCP 客户端调用 `mcp-adapter-discover-abilities`
- **THEN** 返回的能力列表 SHALL 包含 `woocommerce-demo/store-info`

#### Scenario: 执行 WooCommerce 能力
- **WHEN** MCP 客户端调用 `mcp-adapter-execute-ability` 执行 WooCommerce 产品创建能力
- **THEN** WordPress 中 SHALL 创建对应商品，返回成功结果

### Requirement: Demo Abilities 精简
mu-plugin SHALL 移除与 WooCommerce 原生能力重叠的 abilities（`demo/create-post`、`demo/search-posts`），保留 WooCommerce 未覆盖的攻击面 abilities（`demo/list-users`、`demo/upload-media`、`demo/read-file`、`demo/get-settings`）。

影响层: targets/wordpress/mu-plugins/mcp-demo-abilities.php

#### Scenario: 移除重叠 abilities
- **WHEN** MCP 客户端调用 `mcp-adapter-discover-abilities`
- **THEN** 返回列表中不存在 `demo/create-post` 和 `demo/search-posts`

#### Scenario: 保留独有攻击面 abilities
- **WHEN** MCP 客户端调用 `mcp-adapter-discover-abilities`
- **THEN** 返回列表中 SHALL 包含 `demo/list-users`、`demo/upload-media`、`demo/read-file`、`demo/get-settings`

