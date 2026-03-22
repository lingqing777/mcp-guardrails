#!/bin/bash
# WordPress MCP Adapter 自动安装脚本
# 在 WordPress 容器启动后自动执行（后台运行）

MARKER_FILE="/var/www/html/.mcp-setup-done"

# 如果已经安装过且 wp-cli 存在，跳过
# (wp_data 卷上的 marker 可能在容器重建后仍在，但 wp-cli 不在卷上会丢失)
if [ -f "$MARKER_FILE" ] && [ -f /usr/local/bin/wp ]; then
    echo "[WP-MCP] Setup already completed, skipping."
    exit 0
fi

echo "[WP-MCP] Waiting for WordPress to initialize..."

# 等待 WordPress 文件就绪
for i in $(seq 1 60); do
    if [ -f /var/www/html/wp-includes/version.php ]; then
        break
    fi
    sleep 2
done

if [ ! -f /var/www/html/wp-includes/version.php ]; then
    echo "[WP-MCP] ERROR: WordPress files not ready after 120s"
    exit 1
fi

# 等待数据库就绪
echo "[WP-MCP] Waiting for database..."
for i in $(seq 1 30); do
    if php -r "
        \$conn = @new mysqli('wordpress-db', 'wp', 'wp', 'wordpress');
        if (\$conn->connect_error) { exit(1); }
        exit(0);
    " 2>/dev/null; then
        break
    fi
    sleep 2
done

# 安装 wp-cli
echo "[WP-MCP] Installing wp-cli..."
if [ ! -f /usr/local/bin/wp ]; then
    curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    mv wp-cli.phar /usr/local/bin/wp
fi

# 等待 wp-config.php 生成
echo "[WP-MCP] Waiting for wp-config.php..."
for i in $(seq 1 30); do
    if [ -f /var/www/html/wp-config.php ]; then
        break
    fi
    sleep 2
done

# 安装 WordPress (如果尚未安装)
echo "[WP-MCP] Checking WordPress installation..."
if ! wp --allow-root core is-installed 2>/dev/null; then
    echo "[WP-MCP] Installing WordPress core..."
    wp --allow-root core install \
        --url="http://localhost:3000" \
        --title="MCP Guardrails Demo" \
        --admin_user=admin \
        --admin_password=admin123 \
        --admin_email=admin@example.com \
        --skip-email
fi

echo "[WP-MCP] WordPress version: $(wp --allow-root core version)"

# 安装系统依赖 (git, unzip — mcp-adapter 和 wc-mcp-ability 都需要)
echo "[WP-MCP] Installing system dependencies..."
apt-get update -qq && apt-get install -yqq git unzip > /dev/null 2>&1

# 安装 mcp-adapter 插件
echo "[WP-MCP] Installing mcp-adapter plugin..."
cd /var/www/html/wp-content/plugins

if [ ! -d mcp-adapter ]; then
    git clone --depth 1 https://github.com/WordPress/mcp-adapter.git 2>&1
    if [ -d mcp-adapter ]; then
        cd mcp-adapter
        # 安装 Composer (如果没有)
        if [ ! -f /usr/local/bin/composer ]; then
            curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer > /dev/null 2>&1
        fi
        composer install --no-dev --no-interaction 2>&1
        cd /var/www/html
    else
        echo "[WP-MCP] WARNING: git clone failed, mcp-adapter not installed"
    fi
fi

# 激活 mcp-adapter 插件
echo "[WP-MCP] Activating mcp-adapter..."
wp --allow-root plugin activate mcp-adapter 2>&1 || {
    echo "[WP-MCP] WARNING: Could not activate mcp-adapter"
    wp --allow-root plugin list 2>&1
}

# 确认 mu-plugins 挂载正确
echo "[WP-MCP] Checking mu-plugins..."
ls -la /var/www/html/wp-content/mu-plugins/ 2>/dev/null || true

# ========== WooCommerce 安装 ==========
echo "[WP-MCP] Installing WooCommerce..."
if ! wp --allow-root plugin is-installed woocommerce 2>/dev/null; then
    wp --allow-root plugin install woocommerce --activate 2>&1
else
    wp --allow-root plugin activate woocommerce 2>&1 || true
fi
echo "[WP-MCP] WooCommerce version: $(wp --allow-root plugin get woocommerce --field=version 2>/dev/null || echo 'not installed')"

# ========== WooCommerce Sample Data 导入 (XML, 含图片+描述) ==========
echo "[WP-MCP] Checking WooCommerce products..."
PRODUCT_COUNT=$(wp --allow-root post list --post_type=product --format=count 2>/dev/null || echo "0")
if [ "$PRODUCT_COUNT" -eq 0 ] 2>/dev/null; then
    SAMPLE_XML="/var/www/html/wp-content/plugins/woocommerce/sample-data/sample_products.xml"
    if [ -f "$SAMPLE_XML" ]; then
        echo "[WP-MCP] Installing WordPress Importer plugin..."
        wp --allow-root plugin install wordpress-importer --activate 2>&1 || true
        echo "[WP-MCP] Importing WooCommerce sample products (with images)..."
        wp --allow-root import "$SAMPLE_XML" --authors=create --skip=image_resize 2>&1
        NEW_COUNT=$(wp --allow-root post list --post_type=product --format=count 2>/dev/null || echo "0")
        echo "[WP-MCP] Imported products: $NEW_COUNT (with images from WooCommerce CDN)"
    else
        echo "[WP-MCP] WARNING: sample_products.xml not found at $SAMPLE_XML"
    fi
else
    echo "[WP-MCP] Products already exist ($PRODUCT_COUNT), skipping import"
fi

# ========== wc-mcp-ability 插件安装 ==========
echo "[WP-MCP] Installing wc-mcp-ability demo plugin..."
cd /var/www/html/wp-content/plugins
if [ ! -d wc-mcp-ability ]; then
    git clone --depth 1 https://github.com/woocommerce/wc-mcp-ability.git 2>&1 || echo "[WP-MCP] WARNING: git clone wc-mcp-ability failed"
fi
if [ -d wc-mcp-ability ]; then
    wp --allow-root plugin activate wc-mcp-ability 2>&1 || echo "[WP-MCP] WARNING: Could not activate wc-mcp-ability"
fi
cd /var/www/html

# ========== Storefront 主题 ==========
echo "[WP-MCP] Installing Storefront theme..."
wp --allow-root theme install storefront --activate 2>&1 || echo "[WP-MCP] WARNING: Could not install Storefront theme"

# ========== Storefront 店面配置 ==========
echo "[WP-MCP] Configuring storefront..."

# 站点品牌
wp --allow-root option update blogname "TechStyle Store" 2>&1
wp --allow-root option update blogdescription "Premium Apparel & Accessories" 2>&1

# 创建 Storefront Homepage 模板页面（含 Featured/Categories/Recent 分区）
HOMEPAGE_ID=$(wp --allow-root post list --post_type=page --name=shop-home --format=ids 2>/dev/null)
if [ -z "$HOMEPAGE_ID" ]; then
    HOMEPAGE_ID=$(wp --allow-root post create \
        --post_type=page \
        --post_title="Shop Home" \
        --post_status=publish \
        --page_template="template-homepage.php" \
        --porcelain 2>&1)
    echo "[WP-MCP] Created homepage (ID: $HOMEPAGE_ID)"
fi

# 设置首页为 Storefront Homepage 模板页
wp --allow-root option update show_on_front page 2>&1
wp --allow-root option update page_on_front "$HOMEPAGE_ID" 2>&1

# 主题配色和布局
wp --allow-root theme mod set storefront_header_text_color '#ffffff' 2>&1
wp --allow-root theme mod set storefront_heading_color '#333333' 2>&1
wp --allow-root theme mod set storefront_text_color '#6d6d6d' 2>&1
wp --allow-root theme mod set storefront_accent_color '#7f54b3' 2>&1
wp --allow-root theme mod set storefront_product_columns 4 2>&1
wp --allow-root theme mod set storefront_product_rows 4 2>&1

# 确保 WooCommerce 标准页面存在 (Cart/Checkout/My Account)
wp --allow-root wc --user=1 tool run install_pages 2>&1 || true

# ========== WooCommerce 基础配置 ==========
echo "[WP-MCP] Configuring WooCommerce settings..."
wp --allow-root option update woocommerce_currency CNY 2>&1
wp --allow-root option update woocommerce_default_country CN 2>&1
wp --allow-root option update woocommerce_onboarding_profile '{"skipped":true}' --format=json 2>&1 || true
wp --allow-root option update woocommerce_task_list_hidden yes 2>&1 || true

# ========== Permalink 结构 (REST API 需要) ==========
echo "[WP-MCP] Setting permalink structure..."
wp --allow-root rewrite structure '/%postname%/' 2>&1 || true

# ========== WooCommerce REST API Key ==========
echo "[WP-MCP] Creating WooCommerce API Key for MCP Hub..."
WC_KEY_FILE="/var/www/html/.wc-api-key"
if [ ! -f "$WC_KEY_FILE" ]; then
    wp --allow-root eval '
global $wpdb;
$ck = "ck_" . bin2hex(random_bytes(20));
$cs = "cs_" . bin2hex(random_bytes(20));
$wpdb->insert(
    $wpdb->prefix . "woocommerce_api_keys",
    array(
        "user_id" => 1,
        "description" => "MCP Hub Auto",
        "permissions" => "read_write",
        "consumer_key" => wc_api_hash($ck),
        "consumer_secret" => $cs,
        "truncated_key" => substr($ck, -7),
    )
);
file_put_contents("/var/www/html/.wc-api-key", $ck . ":" . $cs);
echo "API Key created: " . substr($ck, 0, 15) . "...\n";
' 2>&1
else
    echo "[WP-MCP] API Key already exists, skipping"
fi

# 修复文件权限
chown -R www-data:www-data /var/www/html/wp-content

# 验证 mcp-adapter serve 命令是否可用
echo "[WP-MCP] Testing mcp-adapter serve command..."
wp --allow-root mcp-adapter --help 2>&1 || echo "[WP-MCP] WARNING: mcp-adapter CLI not available yet"

# 标记安装完成
touch "$MARKER_FILE"
echo "[WP-MCP] ========================================="
echo "[WP-MCP] Setup complete!"
echo "[WP-MCP]   Site: http://localhost:3000"
echo "[WP-MCP]   Admin: http://localhost:3000/wp-admin"
echo "[WP-MCP]   Login: admin / admin123"
echo "[WP-MCP]   WooCommerce: $(wp --allow-root plugin get woocommerce --field=version 2>/dev/null || echo 'N/A')"
if [ -f /var/www/html/.wc-api-key ]; then
    echo "[WP-MCP]   MCP API Key: $(cat /var/www/html/.wc-api-key)"
fi
echo "[WP-MCP] ========================================="
