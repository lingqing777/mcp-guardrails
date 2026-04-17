## 1. 安装 Storefront 主题

- [x] 1.1 在 `targets/wordpress/setup.sh` 的 `# ========== Permalink 结构` 之前追加 Storefront 主题安装和激活命令：`wp --allow-root theme install storefront --activate`（已安装则跳过安装直接激活）

## 2. 配置商店首页

- [x] 2.1 在 `targets/wordpress/setup.sh` 中追加设置首页为静态页面：`wp --allow-root option update show_on_front page`
- [x] 2.2 追加设置 Shop 页面为首页：`wp --allow-root option update page_on_front $(wp --allow-root option get woocommerce_shop_page_id)`

## 3. WooCommerce 基础配置

- [x] 3.1 在 `targets/wordpress/setup.sh` 中追加 WooCommerce 区域和货币设置：`wp --allow-root option update woocommerce_currency CNY`、`wp --allow-root option update woocommerce_default_country CN`
- [x] 3.2 追加跳过 WooCommerce 设置向导标记：`wp --allow-root option update woocommerce_onboarding_profile '{"skipped":true}' --format=json`、`wp --allow-root option update woocommerce_task_list_hidden 'yes'`

## 4. 验证

- [x] 4.1 删除容器内 `.mcp-setup-done` marker 文件，重启 WordPress 容器，确认 setup.sh 自动执行所有新增配置
- [x] 4.2 浏览器打开 `http://localhost:3000`，确认首页显示 Storefront 主题 + 商品网格（18 个 sample 商品）
