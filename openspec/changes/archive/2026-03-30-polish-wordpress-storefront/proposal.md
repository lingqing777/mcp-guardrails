## Why

当前 WordPress 演示站点使用默认主题（Twenty Twenty-Five），首页显示博客文章列表，没有商店页面和商品展示。作为信安作品赛的 WAF1 拦截演示目标，裸装 WordPress 缺乏说服力 — 评委看到的应该是一个"真实运营的电商网店被 AI Agent 攻击"，而不是一个空白的 CMS 安装页。WooCommerce 的 18 个 sample 商品已导入但前台完全不可见。

## What Changes

- 在 `targets/wordpress/setup.sh` 中追加 WooCommerce 店面配置命令：
  - 安装并激活 Storefront 主题（WooCommerce 官方电商主题）
  - 设置首页为 WooCommerce Shop 页面（商品网格展示）
  - 配置 WooCommerce 基础参数（货币 CNY、地区中国、启用分类导航）
  - 创建必要的 WooCommerce 页面（Cart、Checkout、My Account，如不存在）
- 所有改动通过 `wp-cli` 命令完成，不涉及 PHP 代码或主题开发

## Capabilities

### New Capabilities

（无新增独立能力）

### Modified Capabilities

（无 spec 级别的行为变更 — 本变更仅影响 Docker 靶场配置脚本，不涉及 WAF1/WAF2/Dashboard/MCP Hub 的任何需求变更）

## Impact

- **setup.sh**: `targets/wordpress/setup.sh` — 追加 10~15 行 wp-cli 命令
- **WAF1/WAF2**: 无影响 — 不涉及安全检测逻辑
- **Docker 配置**: `targets/wordpress.yml` 无需修改（Storefront 安装在已有容器内）
- **Dashboard**: 无影响 — 无新路由、不影响 5 秒刷新
- **依赖**: Storefront 主题通过 `wp theme install` 从 WordPress.org 安装，无额外依赖
- **路由注册顺序**: 无影响
