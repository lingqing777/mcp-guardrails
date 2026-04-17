## Context

WordPress 演示站点当前状态：
- 主题: Twenty Twenty-Five（WordPress 默认博客主题）
- 首页: 博客文章列表（`show_on_front = posts`）
- WooCommerce: 已安装激活，18 个 sample 商品已导入，但前台不可见
- WooCommerce 页面: Shop 页面存在（page_id=7）但未设为首页
- 站点标题: "MCP Guardrails Demo"

所有配置通过 `targets/wordpress/setup.sh` 中的 `wp-cli` 命令执行，在容器首次初始化时自动完成。setup.sh 使用 marker 文件（`.mcp-setup-done`）实现幂等性。

## Goals / Non-Goals

**Goals:**
- 让 `localhost:3000` 打开后立刻呈现为电商网店（商品网格、分类导航、购物车）
- 使用 WooCommerce 官方 Storefront 主题，保证视觉专业度
- 所有改动通过 setup.sh 的 wp-cli 命令完成，容器重建后可自动复现
- 保持幂等性：已存在的配置不重复执行

**Non-Goals:**
- 不做主题定制开发（不写 CSS/PHP，只用 Storefront 默认外观）
- 不增加额外商品数据（18 个 sample 商品足够演示）
- 不涉及 MCP Hub / WAF1 / WAF2 / Dashboard 的任何改动
- 不修改 `docker-compose.yml` 或 `targets/wordpress.yml`

## Decisions

### 1. 主题选择: Storefront

**选择**: WooCommerce 官方 Storefront 主题
**原因**: 它是 WooCommerce 团队维护的官方电商主题，开箱即用支持商品网格、分类、购物车等电商 UI。通过 `wp theme install storefront --activate` 一行命令安装，不需要额外配置。
**替代方案**: Flavflavor、Flavor 等第三方电商主题 — 但引入非官方主题增加不确定性，且 Storefront 的认知度对评委更有说服力。

### 2. 首页策略: 静态页指向 Shop

**选择**: 设置 `show_on_front = page`，`page_on_front = <shop_page_id>`
**原因**: WooCommerce 的 Shop 页面会自动渲染商品网格，直接作为首页最简单。
**替代方案**: 创建自定义首页 + 独立 Shop 页 — 过度设计，增加复杂度，不影响演示效果。

### 3. WooCommerce 基础配置

通过 `wp option update` 设置：
- 货币: CNY（人民币，贴合国内赛事场景）
- 国家: CN
- WooCommerce 安装向导跳过标记（避免后台显示设置向导弹窗）

### 4. 在 marker 检查之后执行

新增的 wp-cli 命令插入到 setup.sh 的 `touch "$MARKER_FILE"` 之前。由于 marker 文件机制，已经初始化过的容器不会重复执行。对于需要重新配置的场景，删除 `.mcp-setup-done` 重启容器即可。

## Risks / Trade-offs

- **[网络依赖]** `wp theme install storefront` 需要从 WordPress.org 下载主题包 → 在离线环境会失败。缓解: setup.sh 已有同类网络依赖（git clone mcp-adapter），属于可接受风险。
- **[Storefront 版本]** 未锁定版本号，未来 Storefront 更新可能改变外观 → 对于赛事演示场景影响极小，不做版本锁定。
- **[幂等性]** 多次运行 `wp option update` 是安全的（覆盖写入），`wp theme install --activate` 在已安装时会跳过安装直接激活。无风险。
