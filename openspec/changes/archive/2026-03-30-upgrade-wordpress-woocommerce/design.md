## Context

当前 WordPress 演示站点已部署完成（WordPress 6.9.1 + MCP Adapter v0.4.1），但仅有空白内容和 6 个自定义 demo abilities。作为信安作品赛演示，需要一个看起来像真实运营站点的目标应用。WooCommerce（GitHub 9k+ stars）是全球最大的开源电商平台，10.3+ 版本已原生支持 WordPress Abilities API，可通过 MCP Adapter 直接暴露产品/订单管理能力。

现有基础设施：
- `targets/wordpress.yml` — Docker Compose overlay（WordPress + MySQL）
- `targets/wordpress/setup.sh` — 自动安装脚本（wp-cli + mcp-adapter）
- `targets/wordpress/mu-plugins/mcp-demo-abilities.php` — 6 个自定义 abilities
- `config/mcp-servers.json` — 已配置 wordpress server（STDIO 传输）

## Goals / Non-Goals

**Goals:**
- 安装 WooCommerce 10.6+，使站点呈现为真实电商网店
- 导入 WooCommerce 官方 sample data（商品、分类、图片）
- 让 WooCommerce 原生 MCP 能力通过 MCP Adapter 可发现和调用
- 安装 wc-mcp-ability demo 插件提供 `store-info` 能力
- 精简自定义 demo abilities，保留 WooCommerce 未覆盖的攻击面
- 自动化全部安装流程到 setup.sh，一键启动

**Non-Goals:**
- 不修改 MCP Hub、WAF1、WAF2 的任何代码
- 不修改 Dashboard 前端
- 不修改 docker-compose.yml 或 targets/wordpress.yml
- 不配置 WooCommerce 支付网关或运费等业务功能
- 不做 WooCommerce 主题定制

## Decisions

### 1. WooCommerce 版本：使用最新稳定版 10.6+

**理由**: 10.6.1（2026-03-12）是当前最新版，远超 MCP 功能最低要求 10.3。直接 `wp plugin install woocommerce` 即可获取最新版。

**替代方案**: 锁定 10.3 版本 — 拒绝，因为 10.6 是稳定版且包含 MCP 改进。

### 2. Sample Data：使用 WooCommerce 内置 CSV

**理由**: WooCommerce 安装后自带 `sample-data/sample_products.csv`，包含完整商品数据（名称、描述、价格、分类、图片 URL）。通过 WooCommerce 内置 CSV importer 导入，无需额外插件。

**替代方案**: 手动创建商品 — 拒绝，耗时且不如官方数据全面。

### 3. wc-mcp-ability 插件：git clone 安装

**理由**: 与 mcp-adapter 相同的安装方式（git clone 到 plugins/），保持一致性。该插件无 composer 依赖，直接激活即可。

### 4. Demo Abilities 保留策略

保留 WooCommerce 未覆盖的攻击面 abilities，移除与 WooCommerce 原生能力重叠的：

| Ability | 攻击面 | 决定 | 理由 |
|---------|--------|------|------|
| `demo/create-post` | XSS | **移除** | WooCommerce 产品创建覆盖 |
| `demo/search-posts` | SQL 注入 | **移除** | WooCommerce 产品搜索覆盖 |
| `demo/list-users` | 数据泄露 | **保留** | WooCommerce 无用户列表能力 |
| `demo/upload-media` | SSRF | **保留** | WooCommerce 无 URL 上传能力 |
| `demo/read-file` | 路径遍历 | **保留** | WooCommerce 无文件读取能力 |
| `demo/get-settings` | 凭据泄露 | **保留** | WooCommerce 无全站配置能力 |

### 5. 安装流程集成到 setup.sh

**理由**: 所有安装逻辑统一在 setup.sh 中，`docker-compose up -d` 后自动完成全部配置，无需手动操作。

## Risks / Trade-offs

- **[WooCommerce MCP 是 developer preview]** → 能力列表可能与文档不完全一致。缓解：安装后通过 MCP `tools/list` 验证实际暴露的能力。
- **[Sample data 图片需要网络]** → 容器内下载商品图片需要外网访问。缓解：setup.sh 中图片导入失败不阻塞流程，商品数据仍可用。
- **[setup.sh 幂等性]** → WooCommerce 安装和 sample data 导入需要能重复执行不出错。缓解：安装前检查插件是否已存在，导入前检查商品数量。
- **[WooCommerce 需要 MCP 能力显式启用]** → WooCommerce 的 MCP abilities 可能需要在后台手动启用或配置 API key。缓解：setup.sh 中通过 wp-cli 自动配置。
