<?php
/**
 * API Proxy Class - Enhanced Security Mode
 *
 * Routes API calls through WordPress backend, keeping access tokens away from JavaScript.
 * Implements the OAuth2 BCP for Browser-Based Apps security pattern.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_REST_API_Proxy {

    const SESSION_COOKIE_NAME = 'wp_auth_proxy_session';
    const SESSION_DURATION = 3600; // 1 hour default

    private array $proxy_settings = [];
    private ?string $current_session_token = null;
    private ?array $current_session_data = null;

    public function __construct() {
        $this->proxy_settings = WP_REST_Auth_OAuth2_Admin_Settings::get_proxy_settings();

        // Only initialize if proxy is enabled
        if ($this->is_proxy_enabled()) {
            add_action('rest_api_init', [$this, 'register_routes']);
            add_action('init', [$this, 'handle_session_setup']);
        }
    }

    /**
     * Check if proxy is enabled in settings
     */
    public function is_proxy_enabled(): bool {
        return !empty($this->proxy_settings['enable_proxy']);
    }

    /**
     * Register proxy REST routes
     */
    public function register_routes(): void {
        // Main proxy endpoint for all API calls
        register_rest_route('proxy/v1', '/api/(?P<path>.*)', [
            'methods' => ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
            'callback' => [$this, 'proxy_request'],
            'permission_callback' => [$this, 'verify_proxy_session'],
            'args' => [
                'path' => [
                    'required' => true,
                    'type' => 'string',
                    'description' => 'API path to proxy'
                ]
            ]
        ]);

        // Session management endpoints
        register_rest_route('proxy/v1', '/session/create', [
            'methods' => 'POST',
            'callback' => [$this, 'create_session'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('proxy/v1', '/session/validate', [
            'methods' => 'GET',
            'callback' => [$this, 'validate_session'],
            'permission_callback' => [$this, 'verify_proxy_session']
        ]);

        register_rest_route('proxy/v1', '/session/destroy', [
            'methods' => 'POST',
            'callback' => [$this, 'destroy_session'],
            'permission_callback' => [$this, 'verify_proxy_session']
        ]);

        // Proxy info endpoint
        register_rest_route('proxy/v1', '/info', [
            'methods' => 'GET',
            'callback' => [$this, 'proxy_info'],
            'permission_callback' => '__return_true'
        ]);

        // Add CORS support
        add_action('rest_api_init', [$this, 'add_cors_support']);
    }

    /**
     * Handle session setup during init
     */
    public function handle_session_setup(): void {
        $this->current_session_token = $_COOKIE[self::SESSION_COOKIE_NAME] ?? null;

        if ($this->current_session_token) {
            $this->current_session_data = $this->get_session_data($this->current_session_token);
        }
    }

    /**
     * Main proxy request handler
     */
    public function proxy_request(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        $path = $request->get_param('path');
        $method = $request->get_method();
        $body = $request->get_body();
        $headers = $request->get_headers();

        $this->debug_log("Proxy request", [
            'path' => $path,
            'method' => $method,
            'session_id' => $this->current_session_data['id'] ?? 'none'
        ]);

        // Determine target URL based on proxy mode and path
        $target_url = $this->resolve_target_url($path);
        if (is_wp_error($target_url)) {
            return $target_url;
        }

        // Get access token for this session
        $access_token = $this->get_session_access_token();
        if (is_wp_error($access_token)) {
            return $access_token;
        }

        // Make the actual API request
        $response = $this->make_proxied_request($target_url, $method, $body, $headers, $access_token);

        if (is_wp_error($response)) {
            return $response;
        }

        return $this->process_proxy_response($response, $path);
    }

    /**
     * Create a new proxy session
     */
    public function create_session(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        // This endpoint should be called after successful OAuth2/JWT authentication
        // It creates a secure session for the proxy to use

        $auth_method = $request->get_param('auth_method'); // 'jwt' or 'oauth2'
        $credentials = $request->get_param('credentials');

        if (!$auth_method || !$credentials) {
            return wp_auth_oauth2_error_response(
                'missing_credentials',
                'Authentication method and credentials required',
                400
            );
        }

        // Validate credentials and get user/tokens
        $session_data = $this->validate_and_create_session($auth_method, $credentials);

        if (is_wp_error($session_data)) {
            return $session_data;
        }

        // Create secure session token
        $session_token = wp_auth_oauth2_generate_token(64);
        $session_expires = time() + $this->get_session_duration();

        // Store session data securely
        $this->store_session($session_token, $session_data, $session_expires);

        // Set HTTPOnly session cookie
        $cookie_set = wp_auth_oauth2_set_cookie(
            self::SESSION_COOKIE_NAME,
            $session_token,
            $session_expires,
            '/wp-json/proxy/v1/',
            true, // HTTPOnly
            true  // Secure
        );

        if (!$cookie_set) {
            return wp_auth_oauth2_error_response(
                'session_cookie_failed',
                'Failed to set session cookie',
                500
            );
        }

        return wp_auth_oauth2_success_response([
            'session_created' => true,
            'expires_at' => $session_expires,
            'proxy_enabled' => true
        ], 'Proxy session created successfully');
    }

    /**
     * Validate current proxy session
     */
    public function validate_session(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        if (!$this->current_session_data) {
            return wp_auth_oauth2_error_response(
                'no_session',
                'No active proxy session',
                401
            );
        }

        return wp_auth_oauth2_success_response([
            'session_valid' => true,
            'user_id' => $this->current_session_data['user_id'],
            'expires_at' => $this->current_session_data['expires_at'],
            'auth_method' => $this->current_session_data['auth_method']
        ]);
    }

    /**
     * Destroy current proxy session
     */
    public function destroy_session(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        if ($this->current_session_token) {
            $this->delete_session($this->current_session_token);
        }

        // Delete session cookie
        wp_auth_oauth2_delete_cookie(self::SESSION_COOKIE_NAME, '/wp-json/proxy/v1/');

        return wp_auth_oauth2_success_response([
            'session_destroyed' => true
        ]);
    }

    /**
     * Proxy information endpoint
     */
    public function proxy_info(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        return wp_auth_oauth2_success_response([
            'proxy_enabled' => $this->is_proxy_enabled(),
            'proxy_mode' => $this->proxy_settings['proxy_mode'] ?? 'selective',
            'supported_endpoints' => $this->get_supported_endpoints(),
            'session_duration' => $this->get_session_duration(),
            'version' => WP_REST_AUTH_OAUTH2_VERSION
        ]);
    }

    /**
     * Verify proxy session for protected endpoints
     */
    public function verify_proxy_session(): bool {
        if (!$this->current_session_data) {
            return false;
        }

        // Check if session is expired
        if ($this->current_session_data['expires_at'] < time()) {
            $this->delete_session($this->current_session_token);
            return false;
        }

        return true;
    }

    /**
     * Add CORS support for proxy endpoints
     */
    public function add_cors_support(): void {
        add_filter('rest_pre_serve_request', function($served, $result, $request, $server) {
            // Only add CORS for proxy endpoints
            $route = $request->get_route();
            if (strpos($route, '/proxy/v1/') === 0) {
                wp_auth_oauth2_maybe_add_cors_headers();
            }
            return $served;
        }, 15, 4);
    }

    /**
     * Resolve target URL based on path and proxy settings
     */
    private function resolve_target_url(string $path): string|WP_Error {
        // Handle WordPress REST API paths
        if (strpos($path, 'wp/v2/') === 0) {
            if ($this->should_proxy_endpoint('wp_api')) {
                return rest_url($path);
            } else {
                return new WP_Error(
                    'endpoint_not_proxied',
                    'WordPress API endpoints are not configured for proxy',
                    ['status' => 403]
                );
            }
        }

        // Handle OAuth2 endpoints
        if (strpos($path, 'oauth2/v1/') === 0) {
            if ($this->should_proxy_endpoint('oauth2_api')) {
                return rest_url($path);
            } else {
                return new WP_Error(
                    'endpoint_not_proxied',
                    'OAuth2 endpoints are not configured for proxy',
                    ['status' => 403]
                );
            }
        }

        // Handle external APIs
        if ($this->should_proxy_endpoint('external_apis')) {
            return $this->resolve_external_url($path);
        }

        return new WP_Error(
            'unsupported_endpoint',
            'This endpoint is not supported by the proxy',
            ['status' => 400]
        );
    }

    /**
     * Check if specific endpoint type should be proxied
     */
    private function should_proxy_endpoint(string $endpoint_type): bool {
        $endpoints = $this->proxy_settings['proxy_endpoints'] ?? [];
        return !empty($endpoints[$endpoint_type]);
    }

    /**
     * Resolve external API URL
     */
    private function resolve_external_url(string $path): string|WP_Error {
        $allowed_domains = $this->get_allowed_domains();

        // Extract domain from path (assuming format: domain/path/to/endpoint)
        $path_parts = explode('/', ltrim($path, '/'));
        if (empty($path_parts)) {
            return new WP_Error(
                'invalid_external_path',
                'Invalid external API path format',
                ['status' => 400]
            );
        }

        $domain = $path_parts[0];
        $api_path = implode('/', array_slice($path_parts, 1));

        if (!in_array($domain, $allowed_domains)) {
            return new WP_Error(
                'domain_not_allowed',
                sprintf('Domain %s is not in the allowed list', $domain),
                ['status' => 403]
            );
        }

        return 'https://' . $domain . '/' . $api_path;
    }

    /**
     * Get allowed external domains
     */
    private function get_allowed_domains(): array {
        $domains = $this->proxy_settings['allowed_domains'] ?? '';
        return array_filter(array_map('trim', explode("\n", $domains)));
    }

    /**
     * Get access token for current session
     */
    private function get_session_access_token(): string|WP_Error {
        if (!$this->current_session_data) {
            return new WP_Error(
                'no_session',
                'No active session',
                ['status' => 401]
            );
        }

        $auth_method = $this->current_session_data['auth_method'];

        if ($auth_method === 'oauth2') {
            return $this->get_oauth2_access_token();
        } elseif ($auth_method === 'jwt') {
            return $this->current_session_data['access_token'];
        }

        return new WP_Error(
            'unknown_auth_method',
            'Unknown authentication method',
            ['status' => 500]
        );
    }

    /**
     * Get OAuth2 access token (handle refresh if needed)
     */
    private function get_oauth2_access_token(): string|WP_Error {
        $access_token = $this->current_session_data['access_token'] ?? '';
        $token_expires = $this->current_session_data['token_expires_at'] ?? 0;

        // Check if token needs refresh
        if ($token_expires < time() + 300) { // Refresh 5 minutes before expiry
            $refresh_result = $this->refresh_oauth2_token();
            if (is_wp_error($refresh_result)) {
                return $refresh_result;
            }
            $access_token = $refresh_result;
        }

        return $access_token;
    }

    /**
     * Refresh OAuth2 token using refresh token
     */
    private function refresh_oauth2_token(): string|WP_Error {
        // This would integrate with the OAuth2 refresh mechanism
        // For now, return error to indicate refresh needed
        return new WP_Error(
            'token_refresh_needed',
            'OAuth2 token refresh required - please re-authenticate',
            ['status' => 401]
        );
    }

    /**
     * Make the actual proxied HTTP request
     */
    private function make_proxied_request(string $url, string $method, $body, array $headers, string $access_token) {
        $args = [
            'method' => $method,
            'timeout' => 30,
            'headers' => [
                'Authorization' => 'Bearer ' . $access_token,
                'Content-Type' => 'application/json',
                'User-Agent' => 'WP-REST-Auth-Multi-Proxy/' . WP_REST_AUTH_MULTI_VERSION
            ]
        ];

        if (!empty($body)) {
            $args['body'] = $body;
        }

        // Add additional headers from original request (filtered)
        foreach ($headers as $name => $value) {
            $name_lower = strtolower($name);
            if (!in_array($name_lower, ['authorization', 'host', 'cookie'])) {
                $args['headers'][$name] = is_array($value) ? $value[0] : $value;
            }
        }

        $response = wp_remote_request($url, $args);

        if (is_wp_error($response)) {
            return $response;
        }

        return $response;
    }

    /**
     * Process and sanitize proxy response
     */
    private function process_proxy_response($response, string $original_path) {
        $status_code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $headers = wp_remote_retrieve_headers($response);

        // Parse JSON response if applicable
        $data = json_decode($body, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            // Successfully parsed JSON
            $response_data = $data;
        } else {
            // Non-JSON response
            $response_data = $body;
        }

        // Log the proxied request
        $this->debug_log("Proxy response", [
            'path' => $original_path,
            'status' => $status_code,
            'response_type' => is_array($response_data) ? 'json' : 'text'
        ]);

        return new WP_REST_Response($response_data, $status_code);
    }

    /**
     * Validate credentials and create session data
     */
    private function validate_and_create_session(string $auth_method, array $credentials): array|WP_Error {
        if ($auth_method === 'jwt') {
            return $this->create_jwt_session($credentials);
        } elseif ($auth_method === 'oauth2') {
            return $this->create_oauth2_session($credentials);
        }

        return new WP_Error(
            'unsupported_auth_method',
            'Unsupported authentication method',
            ['status' => 400]
        );
    }

    /**
     * Create session from JWT credentials
     */
    private function create_jwt_session(array $credentials): array|WP_Error {
        $access_token = $credentials['access_token'] ?? '';

        if (empty($access_token)) {
            return new WP_Error(
                'missing_access_token',
                'Access token required for JWT session',
                ['status' => 400]
            );
        }

        // Validate JWT token using existing Auth_JWT class
        $auth_jwt = new Auth_JWT();
        $user = $auth_jwt->authenticate_bearer($access_token);

        if (is_wp_error($user)) {
            return $user;
        }

        return [
            'id' => wp_auth_oauth2_generate_token(16),
            'auth_method' => 'jwt',
            'user_id' => $user->ID,
            'access_token' => $access_token,
            'created_at' => time()
        ];
    }

    /**
     * Create session from OAuth2 credentials
     */
    private function create_oauth2_session(array $credentials): array|WP_Error {
        // This would validate OAuth2 tokens and create session
        // Implementation depends on OAuth2 token validation
        return new WP_Error(
            'oauth2_session_not_implemented',
            'OAuth2 proxy sessions not yet implemented',
            ['status' => 501]
        );
    }

    /**
     * Store session data
     */
    private function store_session(string $token, array $data, int $expires_at): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $token_hash = wp_auth_oauth2_hash_token($token, WP_OAUTH2_SECRET);

        $result = $wpdb->insert(
            $table_name,
            [
                'user_id' => $data['user_id'],
                'token_hash' => $token_hash,
                'expires_at' => $expires_at,
                'created_at' => time(),
                'is_revoked' => 0,
                'client_id' => 'proxy_session',
                'scopes' => json_encode(['proxy_access']),
                'token_type' => 'proxy_session'
            ],
            ['%d', '%s', '%d', '%d', '%d', '%s', '%s', '%s']
        );

        // Store additional session data in transient
        if ($result) {
            set_transient(
                'proxy_session_' . $token_hash,
                $data,
                $this->get_session_duration()
            );
        }

        return $result !== false;
    }

    /**
     * Get session data
     */
    private function get_session_data(string $token): ?array {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $token_hash = wp_auth_oauth2_hash_token($token, WP_OAUTH2_SECRET);
        $now = time();

        $session = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE token_hash = %s AND expires_at > %d AND is_revoked = 0 AND token_type = 'proxy_session'",
            $token_hash,
            $now
        ), ARRAY_A);

        if (!$session) {
            return null;
        }

        // Get additional session data from transient
        $session_data = get_transient('proxy_session_' . $token_hash);
        if ($session_data) {
            $session_data['expires_at'] = $session['expires_at'];
            return $session_data;
        }

        return null;
    }

    /**
     * Delete session
     */
    private function delete_session(string $token): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'jwt_refresh_tokens';
        $token_hash = wp_auth_oauth2_hash_token($token, WP_OAUTH2_SECRET);

        // Delete from database
        $result = $wpdb->update(
            $table_name,
            ['is_revoked' => 1],
            ['token_hash' => $token_hash, 'token_type' => 'proxy_session'],
            ['%d'],
            ['%s', '%s']
        );

        // Delete transient
        delete_transient('proxy_session_' . $token_hash);

        return $result !== false;
    }

    /**
     * Get session duration from settings
     */
    private function get_session_duration(): int {
        return $this->proxy_settings['session_duration'] ?? self::SESSION_DURATION;
    }

    /**
     * Get supported endpoints for proxy info
     */
    private function get_supported_endpoints(): array {
        $endpoints = [];
        $proxy_endpoints = $this->proxy_settings['proxy_endpoints'] ?? [];

        if (!empty($proxy_endpoints['wp_api'])) {
            $endpoints[] = 'WordPress REST API (/wp/v2/*)';
        }
        if (!empty($proxy_endpoints['oauth2_api'])) {
            $endpoints[] = 'OAuth2 API (/oauth2/v1/*)';
        }
        if (!empty($proxy_endpoints['external_apis'])) {
            $endpoints[] = 'External APIs';
        }
        if (!empty($proxy_endpoints['user_sensitive'])) {
            $endpoints[] = 'User-sensitive endpoints';
        }

        return $endpoints;
    }

    /**
     * Debug logging
     */
    private function debug_log(string $message, $data = null): void {
        $general_settings = WP_REST_Auth_OAuth2_Admin_Settings::get_general_settings();

        if ($general_settings['enable_debug_logging']) {
            $log_message = "API Proxy Debug: " . $message;
            if ($data !== null) {
                $log_message .= " - " . json_encode($data);
            }
            error_log($log_message);
        }
    }
}