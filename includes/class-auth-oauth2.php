<?php
/**
 * OAuth2 Authentication class (Authorization Code flow simplified)
 */

if (!defined('ABSPATH')) {
    exit;
}

class Auth_OAuth2 {

    const CODE_TTL = 300;     // 5 minutes
    const TOKEN_TTL = 3600;   // 1 hour
    const OPTION_CLIENTS = 'oauth2_clients';
    const OAUTH2_REFRESH_COOKIE_NAME = 'wp_oauth2_refresh_token';
    const REFRESH_TTL = 2592000; // 30 days

    // Store current token scopes for request validation
    private array $current_token_scopes = [];

    // Available OAuth2 scopes and their descriptions
    const AVAILABLE_SCOPES = [
        'read' => 'View your posts, pages, and profile information',
        'write' => 'Create and edit posts and pages',
        'delete' => 'Delete posts and pages',
        'manage_users' => 'View and manage user accounts (admin only)',
        'upload_files' => 'Upload and manage media files',
        'edit_theme' => 'Modify theme and appearance settings (admin only)',
        'moderate_comments' => 'Moderate and manage comments',
        'view_stats' => 'Access website statistics and analytics'
    ];

    public function __construct() {
        add_action('init', [$this, 'handle_authorize_page']);
    }

    public function register_routes(): void {
        register_rest_route('oauth2/v1', '/authorize', [
            'methods' => 'GET',
            'callback' => [$this, 'authorize_endpoint'],
            'permission_callback' => '__return_true',
            'args' => [
                'response_type' => [
                    'required' => true,
                    'type' => 'string',
                    'enum' => ['code']
                ],
                'client_id' => [
                    'required' => true,
                    'type' => 'string'
                ],
                'redirect_uri' => [
                    'required' => true,
                    'type' => 'string',
                    'format' => 'uri'
                ],
                'state' => [
                    'required' => false,
                    'type' => 'string'
                ]
            ]
        ]);

        register_rest_route('oauth2/v1', '/token', [
            'methods' => 'POST',
            'callback' => [$this, 'token_endpoint'],
            'permission_callback' => '__return_true',
            'args' => [
                'grant_type' => [
                    'required' => true,
                    'type' => 'string',
                    'enum' => ['authorization_code']
                ],
                'code' => [
                    'required' => true,
                    'type' => 'string'
                ],
                'redirect_uri' => [
                    'required' => true,
                    'type' => 'string'
                ],
                'client_id' => [
                    'required' => true,
                    'type' => 'string'
                ],
                'client_secret' => [
                    'required' => true,
                    'type' => 'string'
                ]
            ]
        ]);

        register_rest_route('oauth2/v1', '/userinfo', [
            'methods' => 'GET',
            'callback' => [$this, 'userinfo_endpoint'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('oauth2/v1', '/refresh', [
            'methods' => 'POST',
            'callback' => [$this, 'refresh_token_endpoint'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('oauth2/v1', '/logout', [
            'methods' => 'POST',
            'callback' => [$this, 'logout_endpoint'],
            'permission_callback' => '__return_true'
        ]);

        // Add CORS support
        add_action('rest_api_init', [$this, 'add_cors_support']);
    }

    public function handle_authorize_page(): void {
        // Check if this is an OAuth authorize request
        if (isset($_GET['oauth2_authorize'])) {
            $this->process_authorize_request();
        }
    }

    private function process_authorize_request(): void {
        $response_type = $_GET['response_type'] ?? '';
        $client_id = $_GET['client_id'] ?? '';
        $redirect_uri = $_GET['redirect_uri'] ?? '';
        $state = $_GET['state'] ?? '';
        $requested_scope = $_GET['scope'] ?? 'read';

        // Validate parameters
        if ($response_type !== 'code') {
            $this->redirect_with_error($redirect_uri, 'unsupported_response_type', $state);
            return;
        }

        if (empty($client_id) || empty($redirect_uri)) {
            $this->redirect_with_error($redirect_uri, 'invalid_request', $state);
            return;
        }

        $client = $this->get_client($client_id);
        if (!$client) {
            $this->redirect_with_error($redirect_uri, 'unauthorized_client', $state);
            return;
        }

        if (!in_array($redirect_uri, $client['redirect_uris'], true)) {
            $this->redirect_with_error(
                $client['redirect_uris'][0] ?? null,
                'invalid_redirect_uri',
                $state
            );
            return;
        }

        // Validate requested scopes
        $scopes = $this->parse_scopes($requested_scope);
        $valid_scopes = $this->validate_scopes($scopes);

        if (empty($valid_scopes)) {
            $this->redirect_with_error($redirect_uri, 'invalid_scope', $state);
            return;
        }

        if (!is_user_logged_in()) {
            $login_url = wp_login_url(add_query_arg([
                'oauth2_authorize' => '1',
                'response_type' => $response_type,
                'client_id' => $client_id,
                'redirect_uri' => $redirect_uri,
                'state' => $state,
                'scope' => $requested_scope
            ], home_url()));

            wp_redirect($login_url);
            exit;
        }

        $user = wp_get_current_user();

        // Check if user has already consented or if consent is being processed
        if (isset($_POST['oauth2_consent'])) {
            $this->handle_consent_response($client_id, $redirect_uri, $state, $valid_scopes, $user->ID);
            return;
        }

        // Show consent screen
        $this->show_consent_screen($client_id, $redirect_uri, $state, $valid_scopes);
    }

    private function parse_scopes(string $scope_string): array {
        return array_filter(array_map('trim', explode(' ', $scope_string)));
    }

    private function validate_scopes(array $requested_scopes): array {
        $valid_scopes = [];
        $user = wp_get_current_user();

        foreach ($requested_scopes as $scope) {
            if (!array_key_exists($scope, self::AVAILABLE_SCOPES)) {
                continue;
            }

            // Check if user has capability for this scope
            if ($this->user_can_access_scope($user, $scope)) {
                $valid_scopes[] = $scope;
            }
        }

        return $valid_scopes;
    }

    private function user_can_access_scope(WP_User $user, string $scope): bool {
        switch ($scope) {
            case 'read':
                return true; // Everyone can read
            case 'write':
                return user_can($user, 'edit_posts');
            case 'delete':
                return user_can($user, 'delete_posts');
            case 'manage_users':
                return user_can($user, 'list_users');
            case 'upload_files':
                return user_can($user, 'upload_files');
            case 'edit_theme':
                return user_can($user, 'edit_theme_options');
            case 'moderate_comments':
                return user_can($user, 'moderate_comments');
            case 'view_stats':
                return user_can($user, 'view_query_monitor'); // or custom capability
            default:
                return false;
        }
    }

    private function show_consent_screen(string $client_id, string $redirect_uri, string $state, array $scopes): void {
        $user = wp_get_current_user();
        $app_name = $this->get_app_name($client_id);

        // Set content type and start output
        header('Content-Type: text/html; charset=utf-8');

        echo $this->render_consent_page($app_name, $user, $scopes, $client_id, $redirect_uri, $state);
        exit;
    }

    private function get_app_name(string $client_id): string {
        // In a real implementation, this would be stored in the client data
        $app_names = [
            'demo-client' => 'React WordPress OAuth2 Demo'
        ];

        return $app_names[$client_id] ?? 'Third-Party Application';
    }

    private function render_consent_page(string $app_name, WP_User $user, array $scopes, string $client_id, string $redirect_uri, string $state): string {
        $site_name = get_bloginfo('name');
        $user_name = $user->display_name ?: $user->user_login;

        ob_start();
        ?>
        <!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo( 'charset' ); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Authorize <?php echo esc_html($app_name); ?> - <?php echo esc_html($site_name); ?></title>
            <?php
            // Load WordPress admin CSS
            wp_admin_css('login');
            wp_admin_css('buttons');
            ?>
            <style>
                /* WordPress-styled OAuth Consent (Google-inspired layout) */
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                    background: #f6f7f7;
                    margin: 0;
                    padding: 20px;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }

                .oauth-container {
                    background: #fff;
                    border: 1px solid #c3c4c7;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,.1);
                    max-width: 450px;
                    width: 100%;
                    padding: 48px 40px 36px;
                    box-sizing: border-box;
                }

                .wp-header {
                    display: flex;
                    align-items: center;
                    padding: 0 0 24px;
                    border-bottom: 1px solid #e0e0e0;
                    margin-bottom: 32px;
                }

                .wp-logo {
                    width: 24px;
                    height: 24px;
                    background: #0073aa;
                    border-radius: 3px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-right: 12px;
                    color: #fff;
                    font-weight: bold;
                    font-size: 14px;
                }

                .wp-header-text {
                    font-size: 16px;
                    color: #5f6368;
                    margin: 0;
                }

                .oauth-title {
                    font-size: 24px;
                    color: #1d2327;
                    margin: 0 0 8px;
                    font-weight: 400;
                    line-height: 1.3;
                }

                .oauth-subtitle {
                    font-size: 16px;
                    color: #5f6368;
                    margin: 0 0 24px;
                    line-height: 1.5;
                }

                .user-account {
                    display: flex;
                    align-items: center;
                    padding: 12px;
                    background: #f8f9fa;
                    border-radius: 4px;
                    margin-bottom: 32px;
                }

                .user-avatar {
                    width: 32px;
                    height: 32px;
                    background: #0073aa;
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #fff;
                    font-weight: 500;
                    margin-right: 12px;
                }

                .user-details {
                    flex: 1;
                }

                .user-name {
                    font-size: 14px;
                    color: #1d2327;
                    margin: 0 0 2px;
                }

                .user-email {
                    font-size: 12px;
                    color: #5f6368;
                    margin: 0;
                }

                .permissions-intro {
                    font-size: 14px;
                    color: #1d2327;
                    margin: 0 0 20px;
                    line-height: 1.5;
                }

                .app-name {
                    color: #0073aa;
                    font-weight: 500;
                }

                .permissions-list {
                    margin-bottom: 32px;
                }

                .permission-item {
                    display: flex;
                    align-items: flex-start;
                    padding: 16px 0;
                    border-bottom: 1px solid #f0f0f0;
                }

                .permission-item:last-child {
                    border-bottom: none;
                }

                .permission-bullet {
                    width: 8px;
                    height: 8px;
                    background: #0073aa;
                    border-radius: 50%;
                    margin-right: 16px;
                    margin-top: 6px;
                    flex-shrink: 0;
                }

                .permission-text {
                    font-size: 14px;
                    color: #1d2327;
                    line-height: 1.5;
                }

                .trust-section {
                    background: #f8f9fa;
                    border-radius: 4px;
                    padding: 16px;
                    margin-bottom: 32px;
                }

                .trust-title {
                    font-size: 14px;
                    font-weight: 500;
                    color: #1d2327;
                    margin: 0 0 8px;
                }

                .trust-text {
                    font-size: 13px;
                    color: #5f6368;
                    line-height: 1.4;
                    margin: 0 0 12px;
                }

                .trust-link {
                    color: #0073aa;
                    text-decoration: none;
                    font-size: 13px;
                }

                .trust-link:hover {
                    text-decoration: underline;
                }

                .oauth-actions {
                    display: flex;
                    justify-content: flex-end;
                    gap: 12px;
                    padding-top: 16px;
                }

                .btn {
                    padding: 8px 24px;
                    border-radius: 4px;
                    font-size: 14px;
                    font-weight: 500;
                    cursor: pointer;
                    border: 1px solid;
                    text-decoration: none;
                    display: inline-block;
                    text-align: center;
                    min-width: 80px;
                }

                .btn-cancel {
                    background: transparent;
                    color: #0073aa;
                    border-color: #c3c4c7;
                }

                .btn-cancel:hover {
                    background: #f6f7f7;
                }

                .btn-allow {
                    background: #0073aa;
                    color: #fff;
                    border-color: #0073aa;
                }

                .btn-allow:hover {
                    background: #135e96;
                    border-color: #135e96;
                }

                @media screen and (max-width: 480px) {
                    body {
                        padding: 16px;
                    }

                    .oauth-container {
                        padding: 32px 24px 24px;
                    }

                    .oauth-actions {
                        flex-direction: column-reverse;
                    }

                    .btn {
                        width: 100%;
                        margin-bottom: 8px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="oauth-container">
                <!-- WordPress Header (similar to Google's "Sign in with Google") -->
                <div class="wp-header">
                    <div class="wp-logo">W</div>
                    <span class="wp-header-text">Sign in with WordPress</span>
                </div>

                <!-- Main Title -->
                <h1 class="oauth-title"><?php echo esc_html($app_name); ?> wants to access your WordPress Account</h1>

                <!-- User Account Info -->
                <div class="user-account">
                    <div class="user-avatar">
                        <?php echo strtoupper(substr($user_name, 0, 1)); ?>
                    </div>
                    <div class="user-details">
                        <div class="user-name"><?php echo esc_html($user_name); ?></div>
                        <div class="user-email"><?php echo esc_html($user->user_email); ?></div>
                    </div>
                </div>

                <!-- Permissions Introduction -->
                <div class="permissions-intro">
                    This will allow <span class="app-name"><?php echo esc_html($app_name); ?></span> to:
                </div>

                <!-- Permissions List -->
                <div class="permissions-list">
                    <?php foreach ($scopes as $scope): ?>
                        <div class="permission-item">
                            <div class="permission-bullet"></div>
                            <div class="permission-text">
                                <?php echo esc_html(self::AVAILABLE_SCOPES[$scope]); ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>

                <!-- Trust Section -->
                <div class="trust-section">
                    <div class="trust-title">Make sure you trust <?php echo esc_html($app_name); ?></div>
                    <div class="trust-text">
                        You may be sharing sensitive info with this site or app.
                        Learn about how <?php echo esc_html($app_name); ?> will handle your data by
                        reviewing its terms of service and privacy policies. You can always
                        see or remove access in your <a href="<?php echo esc_url(admin_url('profile.php')); ?>" class="trust-link">WordPress Account</a>.
                    </div>
                    <a href="#" class="trust-link" onclick="return false;">Learn about the risks</a>
                </div>

                <!-- Actions -->
                <form method="POST" action="">
                    <input type="hidden" name="client_id" value="<?php echo esc_attr($client_id); ?>">
                    <input type="hidden" name="redirect_uri" value="<?php echo esc_attr($redirect_uri); ?>">
                    <input type="hidden" name="state" value="<?php echo esc_attr($state); ?>">
                    <input type="hidden" name="scope" value="<?php echo esc_attr(implode(' ', $scopes)); ?>">

                    <div class="oauth-actions">
                        <button type="submit" name="oauth2_consent" value="deny" class="btn btn-cancel">
                            Cancel
                        </button>
                        <button type="submit" name="oauth2_consent" value="approve" class="btn btn-allow">
                            Allow
                        </button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    private function get_scope_icon(string $scope): string {
        $icons = [
            'read' => '👁️',
            'write' => '✏️',
            'delete' => '🗑️',
            'manage_users' => '👥',
            'upload_files' => '📁',
            'edit_theme' => '🎨',
            'moderate_comments' => '💬',
            'view_stats' => '📊'
        ];

        return $icons[$scope] ?? '🔧';
    }

    private function handle_consent_response(string $client_id, string $redirect_uri, string $state, array $scopes, int $user_id): void {
        $consent = $_POST['oauth2_consent'] ?? '';

        error_log('OAuth2 Debug: Handling consent response - ' . json_encode([
            'consent' => $consent,
            'client_id' => $client_id,
            'redirect_uri' => $redirect_uri,
            'state' => $state,
            'scopes' => $scopes,
            'user_id' => $user_id
        ]));

        if ($consent !== 'approve') {
            error_log('OAuth2 Debug: Access denied by user');
            $this->redirect_with_error($redirect_uri, 'access_denied', $state);
            return;
        }

        // Generate authorization code
        $code = wp_auth_oauth2_generate_token(32);

        // Store authorization code with approved scopes
        set_transient($this->code_key($code), [
            'client_id' => $client_id,
            'user_id' => $user_id,
            'redirect_uri' => $redirect_uri,
            'scopes' => $scopes,
            'created' => time()
        ], self::CODE_TTL);

        // Redirect back to application with authorization code
        $location = add_query_arg(array_filter([
            'code' => $code,
            'state' => $state
        ]), $redirect_uri);

        error_log('OAuth2 Debug: Redirecting to callback with code - ' . json_encode([
            'code' => substr($code, 0, 10) . '...',
            'state' => $state,
            'redirect_location' => $location
        ]));

        wp_redirect($location);
        exit;
    }

    private function redirect_with_error(?string $redirect_uri, string $error, ?string $state): void {
        if (!$redirect_uri) {
            wp_die("OAuth2 error: $error");
        }

        $params = array_filter([
            'error' => $error,
            'state' => $state
        ]);

        $location = add_query_arg($params, $redirect_uri);
        wp_redirect($location);
        exit;
    }

    public function add_cors_support(): void {
        add_filter('rest_pre_serve_request', function($served, $result, $request, $server) {
            wp_auth_oauth2_maybe_add_cors_headers();
            return $served;
        }, 15, 4);
    }

    public function authorize_endpoint(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        $response_type = $request->get_param('response_type');
        $client_id = $request->get_param('client_id');
        $redirect_uri = $request->get_param('redirect_uri');
        $state = $request->get_param('state');

        if ($response_type !== 'code') {
            return $this->oauth_error_redirect($redirect_uri, 'unsupported_response_type', $state);
        }

        $client = $this->get_client($client_id);
        if (!$client) {
            return $this->oauth_error_redirect($redirect_uri, 'unauthorized_client', $state);
        }

        if (!in_array($redirect_uri, $client['redirect_uris'], true)) {
            return $this->oauth_error_redirect(
                $client['redirect_uris'][0] ?? null,
                'invalid_redirect_uri',
                $state
            );
        }

        if (!is_user_logged_in()) {
            $login_url = wp_login_url(add_query_arg($request->get_query_params(), rest_url('oauth2/v1/authorize')));
            wp_redirect($login_url);
            exit;
        }

        $user = wp_get_current_user();
        $code = wp_auth_oauth2_generate_token(32);

        // Store authorization code
        set_transient($this->code_key($code), [
            'client_id' => $client_id,
            'user_id' => $user->ID,
            'redirect_uri' => $redirect_uri,
            'created' => time()
        ], self::CODE_TTL);

        // Auto-approve for demo (in production, show consent screen)
        $location = add_query_arg(array_filter([
            'code' => $code,
            'state' => $state
        ]), $redirect_uri);

        wp_redirect($location);
        exit;
    }

    public function token_endpoint(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        $grant_type = $request->get_param('grant_type');
        $code = $request->get_param('code');
        $redirect_uri = $request->get_param('redirect_uri');
        $client_id = $request->get_param('client_id');
        $client_secret = $request->get_param('client_secret');

        if ($grant_type !== 'authorization_code') {
            return wp_auth_oauth2_error_response(
                'unsupported_grant_type',
                'Only authorization_code grant type is supported',
                400
            );
        }

        $client = $this->get_client($client_id);
        if (!$client) {
            return wp_auth_oauth2_error_response(
                'invalid_client',
                'Invalid client',
                401
            );
        }

        if (!wp_check_password($client_secret, $client['client_secret'])) {
            return wp_auth_oauth2_error_response(
                'invalid_client',
                'Invalid client credentials',
                401
            );
        }

        $code_data = get_transient($this->code_key($code));
        if (!$code_data) {
            return wp_auth_oauth2_error_response(
                'invalid_grant',
                'Invalid or expired authorization code',
                400
            );
        }

        if ($code_data['client_id'] !== $client_id) {
            return wp_auth_oauth2_error_response(
                'invalid_grant',
                'Authorization code was issued to another client',
                400
            );
        }

        if ($code_data['redirect_uri'] !== $redirect_uri) {
            return wp_auth_oauth2_error_response(
                'invalid_grant',
                'Redirect URI does not match',
                400
            );
        }

        // Consume the authorization code
        delete_transient($this->code_key($code));

        // Generate access token
        $access_token = wp_auth_oauth2_generate_token(48);
        $approved_scopes = $code_data['scopes'] ?? ['read'];

        // Store access token with approved scopes
        set_transient($this->token_key($access_token), [
            'user_id' => $code_data['user_id'],
            'client_id' => $client_id,
            'scopes' => $approved_scopes,
            'created' => time()
        ], self::TOKEN_TTL);

        // Generate refresh token
        $now = time();
        $refresh_token = wp_auth_oauth2_generate_token(64);
        $refresh_expires = $now + self::REFRESH_TTL;

        // Store refresh token in database
        $this->store_oauth2_refresh_token($code_data['user_id'], $refresh_token, $refresh_expires, $client_id, $approved_scopes);

        error_log('OAuth2 Debug: About to set refresh token cookie - ' . json_encode([
            'cookie_name' => self::OAUTH2_REFRESH_COOKIE_NAME,
            'expires_at' => date('Y-m-d H:i:s', $refresh_expires),
            'path' => '/wp-json/oauth2/v1/',
            'user_id' => $code_data['user_id'],
            'client_id' => $client_id
        ]));

        // Set refresh token as HttpOnly cookie
        $cookie_set = wp_auth_oauth2_set_cookie(
            self::OAUTH2_REFRESH_COOKIE_NAME,
            $refresh_token,
            $refresh_expires,
            '/wp-json/oauth2/v1/',
            true,
            true
        );

        error_log('OAuth2 Debug: OAuth2 token exchange successful, cookie set result: ' . ($cookie_set ? 'SUCCESS' : 'FAILED'));

        // Debug: Check what cookies are available after setting
        error_log('OAuth2 Debug: 🍪 Cookies after token exchange: ' . json_encode($_COOKIE));

        return wp_auth_oauth2_success_response([
            'access_token' => $access_token,
            'token_type' => 'Bearer',
            'expires_in' => self::TOKEN_TTL,
            'scope' => implode(' ', $approved_scopes)
        ], 'Token generated successfully', 200);
    }

    public function userinfo_endpoint(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        $user = wp_get_current_user();

        if (!$user || !$user->ID) {
            return wp_auth_oauth2_error_response(
                'unauthorized',
                'Not authenticated',
                401
            );
        }

        // Get scopes from the current access token
        $auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $token = '';
        if (stripos($auth_header, 'Bearer ') === 0) {
            $token = trim(substr($auth_header, 7));
        }

        $token_data = get_transient($this->token_key($token));
        $granted_scopes = $token_data['scopes'] ?? ['read'];

        // Build response data based on granted scopes
        $response_data = [
            'user_id' => (string)$user->ID,
            'granted_scopes' => $granted_scopes
        ];

        // Add user info only if 'read' scope is granted
        if (in_array('read', $granted_scopes)) {
            $response_data['user'] = wp_auth_oauth2_format_user_data($user, true);
        }

        // Add management info if 'manage_users' scope is granted
        if (in_array('manage_users', $granted_scopes) && user_can($user, 'list_users')) {
            $response_data['capabilities'] = [
                'can_manage_users' => true,
                'can_edit_users' => user_can($user, 'edit_users'),
                'can_create_users' => user_can($user, 'create_users')
            ];
        }

        return wp_auth_oauth2_success_response($response_data, 'User info retrieved successfully', 200);
    }

    public function refresh_token_endpoint(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        $refresh_token = $_COOKIE[self::OAUTH2_REFRESH_COOKIE_NAME] ?? '';

        if (empty($refresh_token)) {
            return wp_auth_oauth2_error_response(
                'missing_refresh_token',
                'Refresh token not found',
                401
            );
        }

        $token_data = $this->validate_oauth2_refresh_token($refresh_token);

        if (is_wp_error($token_data)) {
            return $token_data;
        }

        $user = get_user_by('id', $token_data['user_id']);
        if (!$user) {
            return wp_auth_oauth2_error_response(
                'invalid_user',
                'User not found',
                401
            );
        }

        // Generate new access token
        $access_token = wp_auth_oauth2_generate_token(48);
        $approved_scopes = json_decode($token_data['scopes'], true) ?? ['read'];

        // Store access token with approved scopes
        set_transient($this->token_key($access_token), [
            'user_id' => $token_data['user_id'],
            'client_id' => $token_data['client_id'],
            'scopes' => $approved_scopes,
            'created' => time()
        ], self::TOKEN_TTL);

        // Optionally rotate refresh token for better security
        if (apply_filters('wp_auth_oauth2_rotate_oauth2_refresh_token', true)) {
            $now = time();
            $new_refresh_token = wp_auth_oauth2_generate_token(64);
            $refresh_expires = $now + self::REFRESH_TTL;

            // Update refresh token in database
            $this->update_oauth2_refresh_token($token_data['id'], $new_refresh_token, $refresh_expires);

            // Set new refresh token cookie
            wp_auth_oauth2_set_cookie(
                self::OAUTH2_REFRESH_COOKIE_NAME,
                $new_refresh_token,
                $refresh_expires,
                '/wp-json/oauth2/v1/',
                true,
                true
            );
        }

        return wp_auth_oauth2_success_response([
            'access_token' => $access_token,
            'token_type' => 'Bearer',
            'expires_in' => self::TOKEN_TTL,
            'scope' => implode(' ', $approved_scopes)
        ], 'Token refreshed successfully', 200);
    }

    public function logout_endpoint(WP_REST_Request $request) {
        wp_auth_oauth2_maybe_add_cors_headers();

        $refresh_token = $_COOKIE[self::OAUTH2_REFRESH_COOKIE_NAME] ?? '';

        if (!empty($refresh_token)) {
            $this->revoke_oauth2_refresh_token($refresh_token);
        }

        // Delete refresh token cookie
        wp_auth_oauth2_delete_cookie(self::OAUTH2_REFRESH_COOKIE_NAME, '/wp-json/oauth2/v1/');

        return wp_auth_oauth2_success_response([], 'Logout successful', 200);
    }

    public function authenticate_bearer(string $token) {
        $token_data = get_transient($this->token_key($token));

        if (!$token_data) {
            return new WP_Error(
                'invalid_token',
                'Invalid or expired access token',
                ['status' => 401]
            );
        }

        $user = get_user_by('id', (int)$token_data['user_id']);
        if (!$user) {
            return new WP_Error(
                'invalid_token_user',
                'User not found',
                ['status' => 401]
            );
        }

        // Store token scopes for later scope validation
        $this->current_token_scopes = $token_data['scopes'] ?? [];

        $this->debug_log("Bearer authentication successful", [
            'user_id' => $user->ID,
            'token_scopes' => $this->current_token_scopes
        ]);

        // Add scope validation hook for REST API requests
        add_filter('rest_pre_dispatch', [$this, 'validate_request_scopes'], 10, 3);

        wp_set_current_user($user->ID);
        return true;
    }

    private function get_client(string $client_id): ?array {
        if (empty($client_id)) {
            return null;
        }

        // First try to get clients from admin settings
        $oauth2_settings = WP_REST_Auth_OAuth2_Admin_Settings::get_oauth2_settings();
        $clients = $oauth2_settings['clients'] ?? [];

        if (isset($clients[$client_id])) {
            return $clients[$client_id];
        }

        // Fallback to old option for backward compatibility
        $old_clients = get_option(self::OPTION_CLIENTS, []);
        return $old_clients[$client_id] ?? null;
    }

    private function code_key(string $code): string {
        return 'oauth2_code_' . md5($code);
    }

    private function token_key(string $token): string {
        return 'oauth2_token_' . md5($token);
    }

    private function debug_log(string $message, $data = null) {
        $general_settings = WP_REST_Auth_OAuth2_Admin_Settings::get_general_settings();

        if ($general_settings['enable_debug_logging']) {
            $log_message = "OAuth2 Debug: " . $message;
            if ($data !== null) {
                $log_message .= " - " . json_encode($data);
            }
            error_log($log_message);
        }
    }

    private function oauth_error_redirect(?string $redirect_uri = null, string $error = 'invalid_request', ?string $state = null) {
        if (!$redirect_uri) {
            return new WP_Error($error, 'OAuth2 error: ' . $error, ['status' => 400]);
        }

        $params = array_filter([
            'error' => $error,
            'state' => $state
        ]);

        $location = add_query_arg($params, $redirect_uri);

        wp_redirect($location);
        exit;
    }

    public static function upsert_client(string $client_id, string $client_secret, array $redirect_uris): void {
        $clients = get_option(self::OPTION_CLIENTS, []);

        $clients[$client_id] = [
            'client_secret' => wp_hash_password($client_secret),
            'redirect_uris' => array_values($redirect_uris)
        ];

        update_option(self::OPTION_CLIENTS, $clients);
    }

    public function get_clients(): array {
        return get_option(self::OPTION_CLIENTS, []);
    }

    public function revoke_token(string $access_token): bool {
        return delete_transient($this->token_key($access_token));
    }

    public function clean_expired_codes(): void {
        // Transients are automatically cleaned by WordPress
        // This is a placeholder for custom cleanup if needed
    }

    public function validate_redirect_uri(string $client_id, string $redirect_uri): bool {
        $client = $this->get_client($client_id);

        if (!$client) {
            return false;
        }

        return in_array($redirect_uri, $client['redirect_uris'], true);
    }

    /**
     * Validate that the current OAuth2 token has required scopes for the API request
     */
    public function validate_request_scopes($result, $server, $request) {
        // Skip validation if there's already an error or no token scopes stored
        if (is_wp_error($result) || empty($this->current_token_scopes)) {
            return $result;
        }

        $route = $request->get_route();
        $method = $request->get_method();

        // Debug logging
        $this->debug_log("Validating request", [
            'route' => $route,
            'method' => $method,
            'token_scopes' => $this->current_token_scopes
        ]);

        // Get required scopes for this endpoint
        $required_scopes = $this->get_endpoint_required_scopes($route, $method);

        $this->debug_log("Required scopes determined", [
            'method' => $method,
            'route' => $route,
            'required_scopes' => $required_scopes
        ]);

        if (empty($required_scopes)) {
            $this->debug_log("No scopes required for this endpoint, allowing access");
            return $result; // No specific scopes required
        }

        // Check if token has at least one required scope
        $has_required_scope = false;
        foreach ($required_scopes as $required_scope) {
            if (in_array($required_scope, $this->current_token_scopes)) {
                $has_required_scope = true;
                break;
            }
        }

        if (!$has_required_scope) {
            $this->debug_log("Access DENIED - insufficient scope");

            $error_message = sprintf(
                'Insufficient OAuth2 scope. This %s request to %s requires one of the following scopes: [%s]. Your access token only has: [%s]. Please request additional permissions.',
                $method,
                $route,
                implode(', ', $required_scopes),
                implode(', ', $this->current_token_scopes ?: ['none'])
            );

            return new WP_Error(
                'rest_forbidden_scope',
                $error_message,
                [
                    'status' => 403,
                    'oauth2_error' => 'insufficient_scope',
                    'required_scopes' => $required_scopes,
                    'token_scopes' => $this->current_token_scopes,
                    'request_method' => $method,
                    'request_route' => $route,
                    'help' => 'Re-authenticate with broader scopes or contact the application developer.'
                ]
            );
        }

        error_log("OAuth2 Debug: Access GRANTED - scope validation passed");
        return $result;
    }

    /**
     * Map API endpoints to required OAuth2 scopes
     */
    private function get_endpoint_required_scopes(string $route, string $method): array {
        // WordPress REST API endpoint scope mappings
        $endpoint_scopes = [
            // Posts endpoints
            'GET:/wp/v2/posts' => ['read'],
            'POST:/wp/v2/posts' => ['write'],
            'PUT:/wp/v2/posts/*' => ['write'],
            'PATCH:/wp/v2/posts/*' => ['write'],
            'DELETE:/wp/v2/posts/*' => ['delete'],

            // User endpoints
            'GET:/wp/v2/users' => ['read'],
            'GET:/wp/v2/users/*' => ['read'],
            'GET:/wp/v2/users/me' => ['read'],
            'POST:/wp/v2/users' => ['manage_users'],
            'PUT:/wp/v2/users/*' => ['manage_users'],
            'DELETE:/wp/v2/users/*' => ['manage_users'],

            // Media endpoints - reading media info should only require 'read'
            'GET:/wp/v2/media' => ['read'],
            'GET:/wp/v2/media/*' => ['read'],
            'POST:/wp/v2/media' => ['upload_files'],
            'PUT:/wp/v2/media/*' => ['upload_files'],
            'DELETE:/wp/v2/media/*' => ['upload_files'],

            // Comments endpoints
            'GET:/wp/v2/comments' => ['read'],
            'POST:/wp/v2/comments' => ['moderate_comments'],
            'PUT:/wp/v2/comments/*' => ['moderate_comments'],
            'DELETE:/wp/v2/comments/*' => ['moderate_comments'],

            // Categories/Tags endpoints
            'GET:/wp/v2/categories' => ['read'],
            'POST:/wp/v2/categories' => ['manage_categories'],
            'PUT:/wp/v2/categories/*' => ['manage_categories'],
            'DELETE:/wp/v2/categories/*' => ['manage_categories'],

            'GET:/wp/v2/tags' => ['read'],
            'POST:/wp/v2/tags' => ['manage_categories'],
            'PUT:/wp/v2/tags/*' => ['manage_categories'],
            'DELETE:/wp/v2/tags/*' => ['manage_categories'],
        ];

        $route_pattern = $method . ':' . $route;

        // Try exact match first
        if (isset($endpoint_scopes[$route_pattern])) {
            return $endpoint_scopes[$route_pattern];
        }

        // Try wildcard matches for routes with IDs
        foreach ($endpoint_scopes as $pattern => $scopes) {
            if (strpos($pattern, '*') !== false) {
                $regex_pattern = str_replace(['*', '/'], ['[^/]+', '\/'], $pattern);
                if (preg_match('/^' . $regex_pattern . '$/', $route_pattern)) {
                    return $scopes;
                }
            }
        }

        return []; // No specific scopes required
    }

    /**
     * Store OAuth2 refresh token in database
     */
    private function store_oauth2_refresh_token(int $user_id, string $refresh_token, int $expires_at, string $client_id, array $scopes): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'oauth2_refresh_tokens';
        $token_hash = wp_auth_oauth2_hash_token($refresh_token, WP_OAUTH2_SECRET);

        $result = $wpdb->insert(
            $table_name,
            [
                'user_id' => $user_id,
                'token_hash' => $token_hash,
                'expires_at' => $expires_at,
                'created_at' => time(),
                'is_revoked' => 0,
                'client_id' => $client_id, // Store OAuth2 client info
                'scopes' => json_encode($scopes), // Store granted scopes
                'token_type' => 'oauth2' // Distinguish from JWT tokens
            ],
            [
                '%d', '%s', '%d', '%d', '%d', '%s', '%s', '%s'
            ]
        );

        return $result !== false;
    }

    /**
     * Validate OAuth2 refresh token
     */
    private function validate_oauth2_refresh_token(string $refresh_token) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'oauth2_refresh_tokens';
        $token_hash = wp_auth_oauth2_hash_token($refresh_token, WP_OAUTH2_SECRET);
        $now = time();

        $token_data = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE token_hash = %s AND expires_at > %d AND is_revoked = 0 AND token_type = 'oauth2'",
            $token_hash,
            $now
        ), ARRAY_A);

        if (!$token_data) {
            return new WP_Error(
                'invalid_refresh_token',
                'Invalid or expired refresh token',
                ['status' => 401]
            );
        }

        return $token_data;
    }

    /**
     * Update OAuth2 refresh token (for token rotation)
     */
    private function update_oauth2_refresh_token(int $token_id, string $new_refresh_token, int $expires_at): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'oauth2_refresh_tokens';
        $token_hash = wp_auth_oauth2_hash_token($new_refresh_token, WP_OAUTH2_SECRET);

        $result = $wpdb->update(
            $table_name,
            [
                'token_hash' => $token_hash,
                'expires_at' => $expires_at,
                'created_at' => time()
            ],
            ['id' => $token_id],
            ['%s', '%d', '%d'],
            ['%d']
        );

        return $result !== false;
    }

    /**
     * Revoke OAuth2 refresh token
     */
    private function revoke_oauth2_refresh_token(string $refresh_token): bool {
        global $wpdb;

        $table_name = $wpdb->prefix . 'oauth2_refresh_tokens';
        $token_hash = wp_auth_oauth2_hash_token($refresh_token, WP_OAUTH2_SECRET);

        $result = $wpdb->update(
            $table_name,
            ['is_revoked' => 1],
            ['token_hash' => $token_hash, 'token_type' => 'oauth2'],
            ['%d'],
            ['%s', '%s']
        );

        return $result !== false;
    }
}