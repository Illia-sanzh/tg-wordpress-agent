<?php
/**
 * Plugin Name: OpenClaw WP Bridge
 * Description: Exposes WordPress management capabilities to OpenClaw AI agent via the Abilities API, WP-CLI, and REST endpoints.
 * Version: 1.0.0
 * Requires PHP: 7.4
 * Author: OpenClaw Community
 * License: GPL-2.0-or-later
 */

defined( 'ABSPATH' ) || exit;

define( 'OCWB_VERSION', '1.0.0' );
define( 'OCWB_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

// Load Composer autoloader if present (for wordpress/abilities-api, wordpress/php-ai-client).
$autoloader = OCWB_PLUGIN_DIR . 'vendor/autoload.php';
if ( file_exists( $autoloader ) ) {
    require_once $autoloader;
}

/**
 * ─── Abilities API Registration ───
 * Each ability is a discrete WordPress operation that OpenClaw can discover and execute.
 */
add_action( 'wp_abilities_api_init', 'ocwb_register_abilities' );

function ocwb_register_abilities() {

    // ── Content Management ──

    wp_register_ability( 'openclaw/create-post', array(
        'label'       => 'Create Post',
        'description' => 'Create a new WordPress post or page with title, content, status, and optional meta.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'title'      => array( 'type' => 'string', 'description' => 'Post title' ),
                'content'    => array( 'type' => 'string', 'description' => 'Post content (HTML or blocks)' ),
                'status'     => array( 'type' => 'string', 'enum' => array( 'draft', 'publish', 'pending', 'private' ), 'default' => 'draft' ),
                'post_type'  => array( 'type' => 'string', 'default' => 'post' ),
                'categories' => array( 'type' => 'array', 'items' => array( 'type' => 'integer' ) ),
                'tags'       => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
                'meta'       => array( 'type' => 'object', 'additionalProperties' => true ),
            ),
            'required' => array( 'title', 'content' ),
        ),
        'output_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'post_id' => array( 'type' => 'integer' ),
                'url'     => array( 'type' => 'string' ),
            ),
        ),
        'execute_callback'    => 'ocwb_create_post',
        'permission_callback' => function () {
            return current_user_can( 'edit_posts' );
        },
    ) );

    wp_register_ability( 'openclaw/update-post', array(
        'label'       => 'Update Post',
        'description' => 'Update an existing post — title, content, status, or meta fields.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'post_id' => array( 'type' => 'integer' ),
                'title'   => array( 'type' => 'string' ),
                'content' => array( 'type' => 'string' ),
                'status'  => array( 'type' => 'string' ),
                'meta'    => array( 'type' => 'object', 'additionalProperties' => true ),
            ),
            'required' => array( 'post_id' ),
        ),
        'output_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'post_id' => array( 'type' => 'integer' ),
                'url'     => array( 'type' => 'string' ),
            ),
        ),
        'execute_callback'    => 'ocwb_update_post',
        'permission_callback' => function () {
            return current_user_can( 'edit_posts' );
        },
    ) );

    wp_register_ability( 'openclaw/delete-post', array(
        'label'       => 'Delete Post',
        'description' => 'Move a post to trash or permanently delete it.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'post_id' => array( 'type' => 'integer' ),
                'force'   => array( 'type' => 'boolean', 'default' => false ),
            ),
            'required' => array( 'post_id' ),
        ),
        'output_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'deleted' => array( 'type' => 'boolean' ),
            ),
        ),
        'execute_callback'    => 'ocwb_delete_post',
        'permission_callback' => function () {
            return current_user_can( 'delete_posts' );
        },
    ) );

    wp_register_ability( 'openclaw/get-posts', array(
        'label'       => 'Get Posts',
        'description' => 'Query posts with filters — type, status, category, tag, search, date range.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'post_type'   => array( 'type' => 'string', 'default' => 'post' ),
                'status'      => array( 'type' => 'string', 'default' => 'publish' ),
                'numberposts' => array( 'type' => 'integer', 'default' => 10, 'minimum' => 1, 'maximum' => 100 ),
                'search'      => array( 'type' => 'string' ),
                'category'    => array( 'type' => 'integer' ),
                'orderby'     => array( 'type' => 'string', 'default' => 'date' ),
                'order'       => array( 'type' => 'string', 'enum' => array( 'ASC', 'DESC' ), 'default' => 'DESC' ),
            ),
        ),
        'output_schema' => array(
            'type'  => 'array',
            'items' => array( 'type' => 'object' ),
        ),
        'execute_callback'    => 'ocwb_get_posts',
        'permission_callback' => function () {
            return current_user_can( 'read' );
        },
    ) );

    // ── Post Meta ──

    wp_register_ability( 'openclaw/manage-post-meta', array(
        'label'       => 'Manage Post Meta',
        'description' => 'Get, set, or delete post meta fields.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'action'   => array( 'type' => 'string', 'enum' => array( 'get', 'set', 'delete' ) ),
                'post_id'  => array( 'type' => 'integer' ),
                'meta_key' => array( 'type' => 'string' ),
                'meta_value' => array( 'type' => 'string' ),
            ),
            'required' => array( 'action', 'post_id', 'meta_key' ),
        ),
        'output_schema' => array(
            'type' => 'object',
        ),
        'execute_callback'    => 'ocwb_manage_post_meta',
        'permission_callback' => function () {
            return current_user_can( 'edit_posts' );
        },
    ) );

    // ── Plugin Management ──

    wp_register_ability( 'openclaw/manage-plugins', array(
        'label'       => 'Manage Plugins',
        'description' => 'Install, activate, deactivate, update, or delete plugins via WP-CLI.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'action' => array( 'type' => 'string', 'enum' => array( 'install', 'activate', 'deactivate', 'update', 'delete', 'list', 'search' ) ),
                'plugin' => array( 'type' => 'string', 'description' => 'Plugin slug or path' ),
            ),
            'required' => array( 'action' ),
        ),
        'output_schema' => array( 'type' => 'object' ),
        'execute_callback'    => 'ocwb_manage_plugins',
        'permission_callback' => function () {
            return current_user_can( 'install_plugins' );
        },
    ) );

    // ── Theme Management ──

    wp_register_ability( 'openclaw/manage-themes', array(
        'label'       => 'Manage Themes',
        'description' => 'Install, activate, delete, or list themes via WP-CLI.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'action' => array( 'type' => 'string', 'enum' => array( 'install', 'activate', 'delete', 'list', 'search' ) ),
                'theme'  => array( 'type' => 'string', 'description' => 'Theme slug' ),
            ),
            'required' => array( 'action' ),
        ),
        'output_schema' => array( 'type' => 'object' ),
        'execute_callback'    => 'ocwb_manage_themes',
        'permission_callback' => function () {
            return current_user_can( 'install_themes' );
        },
    ) );

    // ── WooCommerce Products ──

    wp_register_ability( 'openclaw/manage-products', array(
        'label'       => 'Manage WooCommerce Products',
        'description' => 'Create, update, delete, or list WooCommerce products.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'action'        => array( 'type' => 'string', 'enum' => array( 'create', 'update', 'delete', 'list', 'get' ) ),
                'product_id'    => array( 'type' => 'integer' ),
                'name'          => array( 'type' => 'string' ),
                'regular_price' => array( 'type' => 'string' ),
                'description'   => array( 'type' => 'string' ),
                'short_description' => array( 'type' => 'string' ),
                'sku'           => array( 'type' => 'string' ),
                'stock_quantity' => array( 'type' => 'integer' ),
                'categories'    => array( 'type' => 'array', 'items' => array( 'type' => 'string' ) ),
                'status'        => array( 'type' => 'string', 'default' => 'publish' ),
            ),
            'required' => array( 'action' ),
        ),
        'output_schema' => array( 'type' => 'object' ),
        'execute_callback'    => 'ocwb_manage_products',
        'permission_callback' => function () {
            return current_user_can( 'edit_products' ) || current_user_can( 'manage_woocommerce' );
        },
    ) );

    // ── Settings ──

    wp_register_ability( 'openclaw/manage-settings', array(
        'label'       => 'Manage Settings',
        'description' => 'Get or update WordPress options/settings.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'action' => array( 'type' => 'string', 'enum' => array( 'get', 'set', 'list' ) ),
                'option_name'  => array( 'type' => 'string' ),
                'option_value' => array( 'type' => 'string' ),
            ),
            'required' => array( 'action' ),
        ),
        'output_schema' => array( 'type' => 'object' ),
        'execute_callback'    => 'ocwb_manage_settings',
        'permission_callback' => function () {
            return current_user_can( 'manage_options' );
        },
    ) );

    // ── Media ──

    wp_register_ability( 'openclaw/upload-media', array(
        'label'       => 'Upload Media',
        'description' => 'Upload a media file from a URL and optionally attach it to a post.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'url'     => array( 'type' => 'string', 'description' => 'Remote file URL to sideload' ),
                'post_id' => array( 'type' => 'integer', 'description' => 'Optional post to attach to' ),
                'title'   => array( 'type' => 'string' ),
                'alt'     => array( 'type' => 'string' ),
            ),
            'required' => array( 'url' ),
        ),
        'output_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'attachment_id' => array( 'type' => 'integer' ),
                'url'           => array( 'type' => 'string' ),
            ),
        ),
        'execute_callback'    => 'ocwb_upload_media',
        'permission_callback' => function () {
            return current_user_can( 'upload_files' );
        },
    ) );

    // ── WP-CLI Pass-through ──

    wp_register_ability( 'openclaw/wpcli', array(
        'label'       => 'Run WP-CLI Command',
        'description' => 'Execute an arbitrary WP-CLI command on the server. Restricted to safe commands.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'command' => array( 'type' => 'string', 'description' => 'WP-CLI command (e.g. "post list --post_type=page --format=json")' ),
            ),
            'required' => array( 'command' ),
        ),
        'output_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'stdout' => array( 'type' => 'string' ),
                'stderr' => array( 'type' => 'string' ),
                'code'   => array( 'type' => 'integer' ),
            ),
        ),
        'execute_callback'    => 'ocwb_run_wpcli',
        'permission_callback' => function () {
            return current_user_can( 'manage_options' );
        },
    ) );

    // ── AI Content Generation (via wordpress/php-ai-client) ──

    wp_register_ability( 'openclaw/ai-generate', array(
        'label'       => 'AI Generate Content',
        'description' => 'Generate text or images using the WordPress AI Client SDK (provider-agnostic).',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(
                'type'        => array( 'type' => 'string', 'enum' => array( 'text', 'image' ) ),
                'prompt'      => array( 'type' => 'string' ),
                'system'      => array( 'type' => 'string', 'description' => 'System instruction for text generation' ),
                'temperature' => array( 'type' => 'number', 'minimum' => 0, 'maximum' => 2 ),
                'max_tokens'  => array( 'type' => 'integer' ),
            ),
            'required' => array( 'prompt' ),
        ),
        'output_schema' => array( 'type' => 'object' ),
        'execute_callback'    => 'ocwb_ai_generate',
        'permission_callback' => function () {
            return current_user_can( 'edit_posts' );
        },
    ) );

    // ── Site Info ──

    wp_register_ability( 'openclaw/site-info', array(
        'label'       => 'Site Info',
        'description' => 'Get comprehensive site information — WP version, active theme, plugins, users, post counts.',
        'input_schema' => array(
            'type'       => 'object',
            'properties' => array(),
        ),
        'output_schema' => array( 'type' => 'object' ),
        'execute_callback'    => 'ocwb_site_info',
        'permission_callback' => function () {
            return current_user_can( 'manage_options' );
        },
    ) );
}

/**
 * ─── Ability Callbacks ───
 */

function ocwb_create_post( $input ) {
    $args = array(
        'post_title'   => sanitize_text_field( $input['title'] ),
        'post_content' => wp_kses_post( $input['content'] ),
        'post_status'  => $input['status'] ?? 'draft',
        'post_type'    => $input['post_type'] ?? 'post',
    );

    if ( ! empty( $input['categories'] ) ) {
        $args['post_category'] = array_map( 'intval', $input['categories'] );
    }

    $post_id = wp_insert_post( $args, true );
    if ( is_wp_error( $post_id ) ) {
        return array( 'error' => $post_id->get_error_message() );
    }

    if ( ! empty( $input['tags'] ) ) {
        wp_set_post_tags( $post_id, $input['tags'] );
    }

    if ( ! empty( $input['meta'] ) && is_array( $input['meta'] ) ) {
        foreach ( $input['meta'] as $key => $value ) {
            update_post_meta( $post_id, sanitize_key( $key ), sanitize_text_field( $value ) );
        }
    }

    return array(
        'post_id' => $post_id,
        'url'     => get_permalink( $post_id ),
    );
}

function ocwb_update_post( $input ) {
    $args = array( 'ID' => intval( $input['post_id'] ) );

    if ( isset( $input['title'] ) ) {
        $args['post_title'] = sanitize_text_field( $input['title'] );
    }
    if ( isset( $input['content'] ) ) {
        $args['post_content'] = wp_kses_post( $input['content'] );
    }
    if ( isset( $input['status'] ) ) {
        $args['post_status'] = sanitize_text_field( $input['status'] );
    }

    $post_id = wp_update_post( $args, true );
    if ( is_wp_error( $post_id ) ) {
        return array( 'error' => $post_id->get_error_message() );
    }

    if ( ! empty( $input['meta'] ) && is_array( $input['meta'] ) ) {
        foreach ( $input['meta'] as $key => $value ) {
            update_post_meta( $post_id, sanitize_key( $key ), sanitize_text_field( $value ) );
        }
    }

    return array(
        'post_id' => $post_id,
        'url'     => get_permalink( $post_id ),
    );
}

function ocwb_delete_post( $input ) {
    $force  = ! empty( $input['force'] );
    $result = wp_delete_post( intval( $input['post_id'] ), $force );
    return array( 'deleted' => (bool) $result );
}

function ocwb_get_posts( $input ) {
    $args = array(
        'post_type'   => $input['post_type'] ?? 'post',
        'post_status' => $input['status'] ?? 'publish',
        'numberposts' => min( intval( $input['numberposts'] ?? 10 ), 100 ),
        'orderby'     => $input['orderby'] ?? 'date',
        'order'       => $input['order'] ?? 'DESC',
    );

    if ( ! empty( $input['search'] ) ) {
        $args['s'] = sanitize_text_field( $input['search'] );
    }
    if ( ! empty( $input['category'] ) ) {
        $args['cat'] = intval( $input['category'] );
    }

    $posts  = get_posts( $args );
    $result = array();

    foreach ( $posts as $post ) {
        $result[] = array(
            'id'      => $post->ID,
            'title'   => $post->post_title,
            'status'  => $post->post_status,
            'date'    => $post->post_date,
            'url'     => get_permalink( $post->ID ),
            'excerpt' => wp_trim_words( $post->post_content, 30 ),
        );
    }

    return $result;
}

function ocwb_manage_post_meta( $input ) {
    $post_id  = intval( $input['post_id'] );
    $meta_key = sanitize_key( $input['meta_key'] );

    switch ( $input['action'] ) {
        case 'get':
            return array( 'value' => get_post_meta( $post_id, $meta_key, true ) );
        case 'set':
            $updated = update_post_meta( $post_id, $meta_key, sanitize_text_field( $input['meta_value'] ?? '' ) );
            return array( 'updated' => (bool) $updated );
        case 'delete':
            $deleted = delete_post_meta( $post_id, $meta_key );
            return array( 'deleted' => (bool) $deleted );
        default:
            return array( 'error' => 'Invalid action' );
    }
}

function ocwb_manage_plugins( $input ) {
    $action = $input['action'];
    $plugin = isset( $input['plugin'] ) ? sanitize_text_field( $input['plugin'] ) : '';

    $command_map = array(
        'install'    => "plugin install {$plugin} --activate",
        'activate'   => "plugin activate {$plugin}",
        'deactivate' => "plugin deactivate {$plugin}",
        'update'     => "plugin update {$plugin}",
        'delete'     => "plugin delete {$plugin}",
        'list'       => 'plugin list --format=json',
        'search'     => "plugin search {$plugin} --format=json --per-page=10",
    );

    if ( ! isset( $command_map[ $action ] ) ) {
        return array( 'error' => 'Invalid action' );
    }

    return ocwb_exec_wpcli( $command_map[ $action ] );
}

function ocwb_manage_themes( $input ) {
    $action = $input['action'];
    $theme  = isset( $input['theme'] ) ? sanitize_text_field( $input['theme'] ) : '';

    $command_map = array(
        'install'  => "theme install {$theme}",
        'activate' => "theme activate {$theme}",
        'delete'   => "theme delete {$theme}",
        'list'     => 'theme list --format=json',
        'search'   => "theme search {$theme} --format=json --per-page=10",
    );

    if ( ! isset( $command_map[ $action ] ) ) {
        return array( 'error' => 'Invalid action' );
    }

    return ocwb_exec_wpcli( $command_map[ $action ] );
}

function ocwb_manage_products( $input ) {
    if ( ! class_exists( 'WooCommerce' ) ) {
        return array( 'error' => 'WooCommerce is not active' );
    }

    $action = $input['action'];

    switch ( $action ) {
        case 'create':
            $product = new \WC_Product_Simple();
            if ( isset( $input['name'] ) ) $product->set_name( sanitize_text_field( $input['name'] ) );
            if ( isset( $input['regular_price'] ) ) $product->set_regular_price( $input['regular_price'] );
            if ( isset( $input['description'] ) ) $product->set_description( wp_kses_post( $input['description'] ) );
            if ( isset( $input['short_description'] ) ) $product->set_short_description( wp_kses_post( $input['short_description'] ) );
            if ( isset( $input['sku'] ) ) $product->set_sku( sanitize_text_field( $input['sku'] ) );
            if ( isset( $input['stock_quantity'] ) ) {
                $product->set_manage_stock( true );
                $product->set_stock_quantity( intval( $input['stock_quantity'] ) );
            }
            $product->set_status( $input['status'] ?? 'publish' );
            $id = $product->save();
            return array( 'product_id' => $id, 'url' => get_permalink( $id ) );

        case 'update':
            $product = wc_get_product( intval( $input['product_id'] ) );
            if ( ! $product ) return array( 'error' => 'Product not found' );
            if ( isset( $input['name'] ) ) $product->set_name( sanitize_text_field( $input['name'] ) );
            if ( isset( $input['regular_price'] ) ) $product->set_regular_price( $input['regular_price'] );
            if ( isset( $input['description'] ) ) $product->set_description( wp_kses_post( $input['description'] ) );
            if ( isset( $input['status'] ) ) $product->set_status( $input['status'] );
            $product->save();
            return array( 'product_id' => $product->get_id(), 'url' => get_permalink( $product->get_id() ) );

        case 'delete':
            $product = wc_get_product( intval( $input['product_id'] ) );
            if ( ! $product ) return array( 'error' => 'Product not found' );
            $product->delete( true );
            return array( 'deleted' => true );

        case 'get':
            $product = wc_get_product( intval( $input['product_id'] ) );
            if ( ! $product ) return array( 'error' => 'Product not found' );
            return array(
                'id'    => $product->get_id(),
                'name'  => $product->get_name(),
                'price' => $product->get_price(),
                'sku'   => $product->get_sku(),
                'stock' => $product->get_stock_quantity(),
                'url'   => get_permalink( $product->get_id() ),
            );

        case 'list':
            return ocwb_exec_wpcli( 'wc product list --format=json --user=1' );

        default:
            return array( 'error' => 'Invalid action' );
    }
}

function ocwb_manage_settings( $input ) {
    switch ( $input['action'] ) {
        case 'get':
            $name = sanitize_text_field( $input['option_name'] ?? '' );
            return array( 'option' => $name, 'value' => get_option( $name ) );

        case 'set':
            $name  = sanitize_text_field( $input['option_name'] ?? '' );
            $value = $input['option_value'] ?? '';
            $updated = update_option( $name, $value );
            return array( 'updated' => $updated );

        case 'list':
            // Return common settings.
            $keys = array( 'blogname', 'blogdescription', 'siteurl', 'home', 'admin_email', 'timezone_string', 'date_format', 'permalink_structure', 'posts_per_page', 'template', 'stylesheet' );
            $result = array();
            foreach ( $keys as $key ) {
                $result[ $key ] = get_option( $key );
            }
            return $result;

        default:
            return array( 'error' => 'Invalid action' );
    }
}

function ocwb_upload_media( $input ) {
    require_once ABSPATH . 'wp-admin/includes/media.php';
    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/image.php';

    $url = esc_url_raw( $input['url'] );
    $tmp = download_url( $url );

    if ( is_wp_error( $tmp ) ) {
        return array( 'error' => $tmp->get_error_message() );
    }

    $file_array = array(
        'name'     => basename( wp_parse_url( $url, PHP_URL_PATH ) ),
        'tmp_name' => $tmp,
    );

    $post_id       = intval( $input['post_id'] ?? 0 );
    $attachment_id = media_handle_sideload( $file_array, $post_id );

    if ( is_wp_error( $attachment_id ) ) {
        @unlink( $tmp );
        return array( 'error' => $attachment_id->get_error_message() );
    }

    if ( ! empty( $input['title'] ) ) {
        wp_update_post( array( 'ID' => $attachment_id, 'post_title' => sanitize_text_field( $input['title'] ) ) );
    }
    if ( ! empty( $input['alt'] ) ) {
        update_post_meta( $attachment_id, '_wp_attachment_image_alt', sanitize_text_field( $input['alt'] ) );
    }

    return array(
        'attachment_id' => $attachment_id,
        'url'           => wp_get_attachment_url( $attachment_id ),
    );
}

function ocwb_ai_generate( $input ) {
    if ( ! class_exists( 'WordPress\\AiClient\\AiClient' ) ) {
        return array( 'error' => 'WordPress AI Client SDK not installed. Run: composer require wordpress/php-ai-client' );
    }

    $type   = $input['type'] ?? 'text';
    $prompt = $input['prompt'];

    try {
        $builder = \WordPress\AiClient\AiClient::prompt( $prompt );

        if ( ! empty( $input['system'] ) ) {
            $builder->usingSystemInstruction( $input['system'] );
        }
        if ( isset( $input['temperature'] ) ) {
            $builder->usingTemperature( floatval( $input['temperature'] ) );
        }
        if ( isset( $input['max_tokens'] ) ) {
            $builder->usingMaxTokens( intval( $input['max_tokens'] ) );
        }

        if ( 'image' === $type ) {
            $image = $builder->generateImage();
            return array( 'type' => 'image', 'result' => $image );
        }

        $text = $builder->generateText();
        return array( 'type' => 'text', 'result' => $text );
    } catch ( \Exception $e ) {
        return array( 'error' => $e->getMessage() );
    }
}

function ocwb_site_info() {
    $active_plugins = get_option( 'active_plugins', array() );
    $theme          = wp_get_theme();

    return array(
        'wp_version'     => get_bloginfo( 'version' ),
        'php_version'    => phpversion(),
        'site_url'       => get_site_url(),
        'site_name'      => get_bloginfo( 'name' ),
        'admin_email'    => get_option( 'admin_email' ),
        'active_theme'   => array(
            'name'    => $theme->get( 'Name' ),
            'version' => $theme->get( 'Version' ),
        ),
        'active_plugins' => $active_plugins,
        'post_count'     => wp_count_posts()->publish,
        'page_count'     => wp_count_posts( 'page' )->publish,
        'user_count'     => count_users()['total_users'],
        'is_multisite'   => is_multisite(),
        'woocommerce'    => class_exists( 'WooCommerce' ),
    );
}

function ocwb_run_wpcli( $input ) {
    $command = $input['command'];

    // Blocklist: dangerous commands that should never be run remotely.
    $blocked = array( 'db drop', 'db reset', 'site empty', 'core update', 'eval', 'eval-file', 'shell' );
    foreach ( $blocked as $b ) {
        if ( stripos( $command, $b ) !== false ) {
            return array( 'error' => "Command blocked for safety: {$b}" );
        }
    }

    return ocwb_exec_wpcli( $command );
}

/**
 * Execute a WP-CLI command safely.
 */
function ocwb_exec_wpcli( $command ) {
    $wp_path = ABSPATH;
    $full    = sprintf( 'wp %s --path=%s 2>&1', $command, escapeshellarg( $wp_path ) );

    $output  = array();
    $code    = 0;
    exec( $full, $output, $code );

    $stdout = implode( "\n", $output );

    // Try to parse JSON output.
    $decoded = json_decode( $stdout, true );
    if ( json_last_error() === JSON_ERROR_NONE ) {
        return array( 'result' => $decoded, 'code' => $code );
    }

    return array( 'stdout' => $stdout, 'code' => $code );
}

/**
 * ─── REST API Endpoints (fallback for direct HTTP access) ───
 */
add_action( 'rest_api_init', function () {
    register_rest_route( 'openclaw/v1', '/execute', array(
        'methods'             => 'POST',
        'callback'            => 'ocwb_rest_execute',
        'permission_callback' => function ( $request ) {
            return current_user_can( 'manage_options' );
        },
    ) );

    register_rest_route( 'openclaw/v1', '/abilities', array(
        'methods'             => 'GET',
        'callback'            => 'ocwb_rest_list_abilities',
        'permission_callback' => function () {
            return current_user_can( 'read' );
        },
    ) );
} );

function ocwb_rest_execute( $request ) {
    $ability_name = sanitize_text_field( $request->get_param( 'ability' ) );
    $input        = $request->get_param( 'input' ) ?? array();

    if ( ! function_exists( 'wp_get_ability' ) ) {
        return new \WP_REST_Response( array( 'error' => 'Abilities API not available' ), 500 );
    }

    $ability = wp_get_ability( $ability_name );
    if ( ! $ability ) {
        return new \WP_REST_Response( array( 'error' => "Unknown ability: {$ability_name}" ), 404 );
    }

    $result = $ability->execute( $input );
    return new \WP_REST_Response( $result, 200 );
}

function ocwb_rest_list_abilities() {
    // Return a list of all registered openclaw abilities.
    $all = array(
        'openclaw/create-post',
        'openclaw/update-post',
        'openclaw/delete-post',
        'openclaw/get-posts',
        'openclaw/manage-post-meta',
        'openclaw/manage-plugins',
        'openclaw/manage-themes',
        'openclaw/manage-products',
        'openclaw/manage-settings',
        'openclaw/upload-media',
        'openclaw/wpcli',
        'openclaw/ai-generate',
        'openclaw/site-info',
    );

    $result = array();
    foreach ( $all as $name ) {
        if ( function_exists( 'wp_get_ability' ) ) {
            $ability = wp_get_ability( $name );
            if ( $ability ) {
                $result[] = array(
                    'name'        => $name,
                    'label'       => $ability->label ?? $name,
                    'description' => $ability->description ?? '',
                );
                continue;
            }
        }
        $result[] = array( 'name' => $name );
    }

    return new \WP_REST_Response( $result, 200 );
}
