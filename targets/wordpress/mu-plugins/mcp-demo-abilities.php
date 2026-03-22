<?php
/**
 * Plugin Name: MCP Demo Abilities
 * Description: 注册用于 MCP Guardrails 安全演示的 WordPress Abilities
 * Version: 1.0.0
 *
 * 这些 abilities 通过 mcp-adapter 暴露给 AI Agent，
 * 用于展示 WAF1 对不同攻击向量的拦截能力。
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * 允许 WooCommerce MCP 在 HTTP 下运行（本地开发环境）
 * WooCommerce MCP 默认要求 HTTPS，此 filter 为本地演示环境关闭该限制
 */
add_filter( 'woocommerce_mcp_allow_insecure_transport', '__return_true' );

/**
 * 注册 demo ability categories
 * 必须在 abilities 注册之前完成
 */
add_action( 'wp_abilities_api_categories_init', 'mcp_demo_register_categories' );

function mcp_demo_register_categories() {
    if ( ! function_exists( 'wp_register_ability_category' ) ) {
        return;
    }

    wp_register_ability_category( 'content', array(
        'label'       => 'Content',
        'description' => 'Content management abilities',
    ) );
    wp_register_ability_category( 'users', array(
        'label'       => 'Users',
        'description' => 'User management abilities',
    ) );
    wp_register_ability_category( 'media', array(
        'label'       => 'Media',
        'description' => 'Media management abilities',
    ) );
    wp_register_ability_category( 'system', array(
        'label'       => 'System',
        'description' => 'System information abilities',
    ) );
}

/**
 * 注册 demo abilities
 * 使用 wp_abilities_api_init 钩子确保 Abilities API 已加载
 */
add_action( 'wp_abilities_api_init', 'mcp_demo_register_abilities' );

function mcp_demo_register_abilities() {
    // 检查函数是否存在 (WordPress 6.9+ 或 abilities-api 插件)
    if ( ! function_exists( 'wp_register_ability' ) ) {
        return;
    }

    // 注: demo/create-post 和 demo/search-posts 已移除，
    // 由 WooCommerce 原生 MCP 能力（产品创建/搜索）覆盖。

    // ========== 1. demo/list-users ==========
    // 攻击面: Sensitive Data Exposure (用户信息)
    wp_register_ability( 'demo/list-users', array(
        'label'       => 'List Users',
        'description' => 'List WordPress users with basic info.',
        'category'    => 'users',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'role' => array(
                    'type'        => 'string',
                    'description' => 'Filter by role: administrator, editor, author, subscriber',
                    'default'     => '',
                ),
            ),
        ),
        'permission_callback' => function () {
            return current_user_can( 'list_users' );
        },
        'execute_callback' => function ( $params ) {
            $args = array( 'number' => 50 );
            if ( ! empty( $params['role'] ) ) {
                $args['role'] = sanitize_text_field( $params['role'] );
            }
            $users = get_users( $args );

            return array(
                'count' => count( $users ),
                'users' => array_map( function ( $user ) {
                    return array(
                        'id'       => $user->ID,
                        'username' => $user->user_login,
                        'email'    => $user->user_email,
                        'role'     => implode( ', ', $user->roles ),
                    );
                }, $users ),
            );
        },
        'meta' => array(
            'mcp' => array(
                'public' => true,
                'type'   => 'tool',
            ),
        ),
    ) );

    // ========== 4. demo/upload-media ==========
    // 攻击面: SSRF (url 参数)
    wp_register_ability( 'demo/upload-media', array(
        'label'       => 'Upload Media',
        'description' => 'Upload media to WordPress from a URL.',
        'category'    => 'media',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'url' => array(
                    'type'        => 'string',
                    'description' => 'URL of the media file to download and upload',
                ),
                'title' => array(
                    'type'        => 'string',
                    'description' => 'Title for the media item',
                    'default'     => '',
                ),
            ),
            'required'   => array( 'url' ),
        ),
        'permission_callback' => function () {
            return current_user_can( 'upload_files' );
        },
        'execute_callback' => function ( $params ) {
            require_once ABSPATH . 'wp-admin/includes/media.php';
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/image.php';

            $url = esc_url_raw( $params['url'] );
            $tmp = download_url( $url, 30 );

            if ( is_wp_error( $tmp ) ) {
                return array( 'error' => 'Download failed: ' . $tmp->get_error_message() );
            }

            $file_array = array(
                'name'     => basename( parse_url( $url, PHP_URL_PATH ) ) ?: 'upload',
                'tmp_name' => $tmp,
            );

            $attachment_id = media_handle_sideload( $file_array, 0, $params['title'] ?? '' );

            if ( is_wp_error( $attachment_id ) ) {
                @unlink( $tmp );
                return array( 'error' => $attachment_id->get_error_message() );
            }

            return array(
                'success'       => true,
                'attachment_id' => $attachment_id,
                'url'           => wp_get_attachment_url( $attachment_id ),
            );
        },
        'meta' => array(
            'mcp' => array(
                'public' => true,
                'type'   => 'tool',
            ),
        ),
    ) );

    // ========== 5. demo/read-file ==========
    // 攻击面: Path Traversal, Sensitive Files
    wp_register_ability( 'demo/read-file', array(
        'label'       => 'Read File',
        'description' => 'Read a file from the WordPress installation directory.',
        'category'    => 'system',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'path' => array(
                    'type'        => 'string',
                    'description' => 'Relative file path within WordPress directory (e.g., readme.html)',
                ),
            ),
            'required'   => array( 'path' ),
        ),
        'permission_callback' => function () {
            return current_user_can( 'manage_options' );
        },
        'execute_callback' => function ( $params ) {
            $base = ABSPATH;
            $path = $base . ltrim( $params['path'], '/' );
            $real = realpath( $path );

            // 安全检查: 确保路径在 WordPress 目录内
            if ( ! $real || strpos( $real, realpath( $base ) ) !== 0 ) {
                return array( 'error' => 'Invalid path or access denied' );
            }

            if ( ! is_file( $real ) || ! is_readable( $real ) ) {
                return array( 'error' => 'File not found or not readable' );
            }

            $content = file_get_contents( $real );

            return array(
                'path'    => $params['path'],
                'size'    => strlen( $content ),
                'content' => mb_substr( $content, 0, 5000 ),
            );
        },
        'meta' => array(
            'mcp' => array(
                'public' => true,
                'type'   => 'tool',
            ),
        ),
    ) );

    // ========== 6. demo/get-settings ==========
    // 攻击面: Secrets / Credential Exposure
    wp_register_ability( 'demo/get-settings', array(
        'label'       => 'Get Settings',
        'description' => 'Get WordPress site settings and configuration.',
        'category'    => 'system',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'section' => array(
                    'type'        => 'string',
                    'description' => 'Settings section: general, reading, writing, discussion',
                    'default'     => 'general',
                ),
            ),
        ),
        'permission_callback' => function () {
            return current_user_can( 'manage_options' );
        },
        'execute_callback' => function ( $params ) {
            $section = $params['section'] ?? 'general';

            $settings = array(
                'general' => array(
                    'blogname'        => get_option( 'blogname' ),
                    'blogdescription' => get_option( 'blogdescription' ),
                    'siteurl'         => get_option( 'siteurl' ),
                    'home'            => get_option( 'home' ),
                    'admin_email'     => get_option( 'admin_email' ),
                    'timezone_string' => get_option( 'timezone_string' ),
                    'date_format'     => get_option( 'date_format' ),
                ),
                'reading' => array(
                    'posts_per_page'   => get_option( 'posts_per_page' ),
                    'show_on_front'    => get_option( 'show_on_front' ),
                    'blog_public'      => get_option( 'blog_public' ),
                ),
                'writing' => array(
                    'default_category' => get_option( 'default_category' ),
                    'default_post_format' => get_option( 'default_post_format' ),
                ),
            );

            if ( isset( $settings[ $section ] ) ) {
                return $settings[ $section ];
            }

            return array( 'error' => "Unknown section: {$section}" );
        },
        'meta' => array(
            'mcp' => array(
                'public' => true,
                'type'   => 'tool',
            ),
        ),
    ) );
}
