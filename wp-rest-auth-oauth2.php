<?php
/**
 * Plugin Name: OAuth2 Auth Pro WP REST API
 * Plugin URI: https://github.com/juanma-wp/wp-rest-auth-oauth2
 * Description: Secure OAuth2 authentication for headless WordPress, SPAs, and mobile apps. No bloat, no upselling.
 * Version: 1.0.0
 * Author: Juan Manuel Garrido
 * Author URI: https://github.com/juanma-wp
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: oauth2-auth-pro-wp-rest-api
 *
 * OAuth2 server implementation for WordPress REST API with:
 * - Complete OAuth2 Authorization Code flow with PKCE support (RFC 7636)
 * - Scope-based permissions with automatic endpoint enforcement
 * - Refresh token rotation for enhanced security
 * - Multi-client support with admin interface
 * - Built-in user consent screen
 * - Perfect for mobile apps, SPAs, and headless WordPress
 */

if (!defined('ABSPATH')) {
    exit;
}

// Load Composer autoloader
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

define('WP_REST_AUTH_OAUTH2_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('WP_REST_AUTH_OAUTH2_PLUGIN_URL', plugin_dir_url(__FILE__));
define('WP_REST_AUTH_OAUTH2_VERSION', '1.0.0');

class WP_REST_Auth_OAuth2 {

    private $auth_oauth2;
    private $admin_settings;

    public function __construct() {
        add_action('plugins_loaded', [$this, 'init']);
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    }

    public function init() {
        $this->load_dependencies();
        $this->setup_constants();
        $this->init_hooks();
    }

    private function load_dependencies() {
        require_once WP_REST_AUTH_OAUTH2_PLUGIN_DIR . 'includes/helpers.php';
        require_once WP_REST_AUTH_OAUTH2_PLUGIN_DIR . 'includes/class-oauth2-cookie-config.php';
        require_once WP_REST_AUTH_OAUTH2_PLUGIN_DIR . 'includes/class-admin-settings.php';
        require_once WP_REST_AUTH_OAUTH2_PLUGIN_DIR . 'includes/class-auth-oauth2.php';

        // Initialize admin settings
        if (is_admin()) {
            $this->admin_settings = new WP_REST_Auth_OAuth2_Admin_Settings();
        }

        $this->auth_oauth2 = new Auth_OAuth2();
    }

    private function setup_constants() {
        // Setup a secret for OAuth2 token hashing
        if (!defined('WP_OAUTH2_SECRET')) {
            $secret = get_option('wp_oauth2_secret');
            if (!$secret) {
                $secret = wp_generate_password(64, false);
                update_option('wp_oauth2_secret', $secret);
            }
            define('WP_OAUTH2_SECRET', $secret);
        }
    }

    private function init_hooks() {
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        add_filter('rest_authentication_errors', [$this, 'maybe_auth_bearer'], 20);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_scripts']);
    }

    public function register_rest_routes() {
        $this->auth_oauth2->register_routes();
    }

    public function maybe_auth_bearer($result) {
        error_log('OAuth2 Debug: maybe_auth_bearer called - result: ' . json_encode($result));

        if (!empty($result)) {
            error_log('OAuth2 Debug: Result already set, returning early');
            return $result;
        }

        $auth_header = $this->get_auth_header();
        error_log('OAuth2 Debug: Auth header: ' . ($auth_header ?: 'NONE'));

        if (!$auth_header || stripos($auth_header, 'Bearer ') !== 0) {
            error_log('OAuth2 Debug: No Bearer token found in header');
            return $result;
        }

        $token = trim(substr($auth_header, 7));
        error_log('OAuth2 Debug: Extracted token: ' . substr($token, 0, 10) . '...');

        // Try OAuth2 authentication
        $oauth_result = $this->auth_oauth2->authenticate_bearer($token);
        error_log('OAuth2 Debug: OAuth2 auth result: ' . (is_wp_error($oauth_result) ? $oauth_result->get_error_message() : 'SUCCESS'));

        if (is_wp_error($oauth_result)) {
            return $oauth_result;
        }

        // Authentication succeeded, return null to allow default handling
        error_log('OAuth2 Debug: Returning null to allow default handling, user: ' . get_current_user_id());
        return null;
    }

    private function get_auth_header() {
        $auth_header = '';

        // Try various ways to get the Authorization header
        if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
        } elseif (isset($_SERVER['Authorization'])) {
            $auth_header = $_SERVER['Authorization'];
        } elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            // Handle Apache with mod_rewrite
            $auth_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        } elseif (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth_header = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        } elseif (function_exists('getallheaders')) {
            $headers = getallheaders();
            $auth_header = $headers['Authorization'] ?? $headers['authorization'] ?? '';
        }

        error_log('OAuth2 Debug: Raw $_SERVER keys: ' . implode(', ', array_keys($_SERVER)));

        return $auth_header;
    }

    public function activate() {
        $this->create_oauth_tables();
        $this->create_demo_client();
    }

    public function deactivate() {
        // Clean up expired tokens on deactivation
        global $wpdb;
        $table_name = $wpdb->prefix . 'oauth2_refresh_tokens';
        $wpdb->query("DELETE FROM {$table_name} WHERE expires_at < " . time());
    }

    private function create_oauth_tables() {
        global $wpdb;

        // Reuse JWT table structure but add OAuth2-specific columns
        $table_name = $wpdb->prefix . 'oauth2_refresh_tokens';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            user_id bigint(20) NOT NULL,
            token_hash varchar(255) NOT NULL,
            expires_at bigint(20) NOT NULL,
            revoked_at bigint(20) DEFAULT NULL,
            issued_at bigint(20) NOT NULL,
            user_agent varchar(500) DEFAULT NULL,
            ip_address varchar(45) DEFAULT NULL,
            created_at bigint(20) DEFAULT NULL,
            is_revoked tinyint(1) DEFAULT 0,
            client_id varchar(255) DEFAULT NULL,
            scopes text DEFAULT NULL,
            token_type varchar(50) DEFAULT 'oauth2',
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY token_hash (token_hash),
            KEY expires_at (expires_at),
            KEY client_id (client_id),
            KEY token_type (token_type)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    private function create_demo_client() {
        // Get settings directly without using the admin class (which may not be loaded during activation)
        $settings = get_option('wp_rest_auth_oauth2_settings', []);
        $clients = $settings['clients'] ?? [];

        // Always update the demo client to ensure correct redirect URIs
        if (!isset($clients['demo-client'])) {
            $clients['demo-client'] = [
                'name' => 'Demo OAuth2 Client',
                'client_secret' => wp_hash_password('demo-secret'),
                'redirect_uris' => [
                    'http://localhost:3000/callback',
                    'http://localhost:5173/callback',
                    'http://localhost:5174/callback',
                    'http://localhost:5175/callback',
                    'https://example.com/callback'
                ],
                'created_at' => current_time('mysql')
            ];

            // Update settings
            $settings['clients'] = $clients;
            update_option('wp_rest_auth_oauth2_settings', $settings);
        }
    }

    public function enqueue_scripts() {
        if (is_admin()) {
            wp_enqueue_script(
                'wp-rest-auth-oauth2-admin',
                WP_REST_AUTH_OAUTH2_PLUGIN_URL . 'assets/admin.js',
                ['jquery'],
                WP_REST_AUTH_OAUTH2_VERSION,
                true
            );

            wp_localize_script('wp-rest-auth-oauth2-admin', 'wpRestAuthOAuth2', [
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('wp_rest_auth_oauth2_nonce'),
                'restUrl' => rest_url()
            ]);
        }
    }
}

new WP_REST_Auth_OAuth2();