<?php
/**
 * Admin Settings for WP REST Auth OAuth2
 * Configuration for OAuth2 authentication
 */

if (!defined('ABSPATH')) {
    exit;
}

class WP_REST_Auth_OAuth2_Admin_Settings {

    const OPTION_GROUP = 'wp_rest_auth_oauth2_settings';
    const OPTION_OAUTH2_SETTINGS = 'wp_rest_auth_oauth2_settings';
    const OPTION_GENERAL_SETTINGS = 'wp_rest_auth_oauth2_general_settings';

    public function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);

        // AJAX handlers for OAuth2 client management
        add_action('wp_ajax_add_oauth2_client', [$this, 'ajax_add_oauth2_client']);
        add_action('wp_ajax_delete_oauth2_client', [$this, 'ajax_delete_oauth2_client']);
    }

    public function add_admin_menu() {
        add_options_page(
            'WP REST Auth OAuth2 Settings',
            'WP REST Auth OAuth2',
            'manage_options',
            'wp-rest-auth-oauth2',
            [$this, 'admin_page']
        );
    }

    public function register_settings() {
        // Register setting groups
        register_setting(self::OPTION_GROUP, self::OPTION_OAUTH2_SETTINGS, [
            'sanitize_callback' => [$this, 'sanitize_oauth2_settings']
        ]);

        register_setting(self::OPTION_GROUP, self::OPTION_GENERAL_SETTINGS, [
            'sanitize_callback' => [$this, 'sanitize_general_settings']
        ]);

        register_setting(
            self::OPTION_GROUP,
            'oauth2_auth_cookie_config',
            [
                'type' => 'array',
                'sanitize_callback' => [$this, 'sanitize_cookie_settings'],
                'default' => [
                    'samesite' => 'auto',
                    'secure' => 'auto',
                    'path' => 'auto',
                    'domain' => 'auto',
                ],
            ]
        );

        // General Settings Section
        add_settings_section(
            'general_settings',
            'General Settings',
            [$this, 'general_settings_section'],
            'wp-rest-auth-oauth2-general'
        );

        add_settings_field(
            'enable_debug_logging',
            'Enable Debug Logging',
            [$this, 'enable_debug_logging_field'],
            'wp-rest-auth-oauth2-general',
            'general_settings'
        );

        add_settings_field(
            'cors_allowed_origins',
            'CORS Allowed Origins',
            [$this, 'cors_allowed_origins_field'],
            'wp-rest-auth-oauth2-general',
            'general_settings'
        );

        // Cookie Configuration Section (on its own tab)
        add_settings_section(
            'cookie_config_section',
            'Cookie Configuration',
            [$this, 'cookie_config_section'],
            'wp-rest-auth-oauth2-cookies'
        );

        add_settings_field(
            'cookie_samesite',
            'SameSite Attribute',
            [$this, 'cookie_samesite_field'],
            'wp-rest-auth-oauth2-cookies',
            'cookie_config_section'
        );

        add_settings_field(
            'cookie_secure',
            'Secure Attribute',
            [$this, 'cookie_secure_field'],
            'wp-rest-auth-oauth2-cookies',
            'cookie_config_section'
        );

        add_settings_field(
            'cookie_path',
            'Cookie Path',
            [$this, 'cookie_path_field'],
            'wp-rest-auth-oauth2-cookies',
            'cookie_config_section'
        );

        add_settings_field(
            'cookie_domain',
            'Cookie Domain',
            [$this, 'cookie_domain_field'],
            'wp-rest-auth-oauth2-cookies',
            'cookie_config_section'
        );
    }

    public function enqueue_admin_scripts($hook) {
        if ($hook !== 'settings_page_wp-rest-auth-oauth2') {
            return;
        }

        wp_enqueue_script(
            'wp-rest-auth-oauth2-admin',
            plugin_dir_url(dirname(__FILE__)) . 'assets/admin.js',
            ['jquery'],
            '1.0.0',
            true
        );

        wp_localize_script('wp-rest-auth-oauth2-admin', 'wpRestAuthOAuth2', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp_rest_auth_oauth2_nonce')
        ]);
    }

    public function admin_page() {
        $active_tab = $_GET['tab'] ?? 'oauth2';
        ?>
        <div class="wrap">
            <h1>🔐 WP REST Auth OAuth2 Settings</h1>
            <p class="description">OAuth2 authentication for WordPress REST API</p>

            <nav class="nav-tab-wrapper">
                <a href="?page=wp-rest-auth-oauth2&tab=oauth2" class="nav-tab <?php echo $active_tab == 'oauth2' ? 'nav-tab-active' : ''; ?>">OAuth2 Settings</a>
                <a href="?page=wp-rest-auth-oauth2&tab=general" class="nav-tab <?php echo $active_tab == 'general' ? 'nav-tab-active' : ''; ?>">General Settings</a>
                <a href="?page=wp-rest-auth-oauth2&tab=cookies" class="nav-tab <?php echo $active_tab == 'cookies' ? 'nav-tab-active' : ''; ?>">Cookie Settings</a>
                <a href="?page=wp-rest-auth-oauth2&tab=help" class="nav-tab <?php echo $active_tab == 'help' ? 'nav-tab-active' : ''; ?>">Help & Documentation</a>
            </nav>

            <?php if ($active_tab == 'help'): ?>
                <?php $this->render_help_tab(); ?>
            <?php else: ?>
                <form method="post" action="options.php">
                    <?php
                    settings_fields(self::OPTION_GROUP);

                    if ($active_tab == 'oauth2') {
                        $this->render_oauth2_tab();
                    } elseif ($active_tab == 'general') {
                        do_settings_sections('wp-rest-auth-oauth2-general');
                        submit_button();
                    } elseif ($active_tab == 'cookies') {
                        do_settings_sections('wp-rest-auth-oauth2-cookies');
                        submit_button();
                    }
                    ?>
                </form>
            <?php endif; ?>
        </div>
        <?php
    }

    private function render_oauth2_tab() {
        $oauth2_settings = get_option(self::OPTION_OAUTH2_SETTINGS, []);
        $clients = $oauth2_settings['clients'] ?? [];
        ?>
        <div class="oauth2-settings">
            <h2>OAuth2 Client Management</h2>
            <p>Configure OAuth2 clients that can authenticate with your WordPress site using the Authorization Code flow.</p>

            <div class="oauth2-add-client">
                <h3>Add New OAuth2 Client</h3>
                <table class="form-table">
                    <tr>
                        <th><label for="new_client_name">Client Name</label></th>
                        <td><input type="text" id="new_client_name" class="regular-text" placeholder="My React App" /></td>
                    </tr>
                    <tr>
                        <th><label for="new_client_id">Client ID</label></th>
                        <td>
                            <input type="text" id="new_client_id" class="regular-text" placeholder="my-react-app" />
                            <button type="button" id="generate_client_id" class="button">Generate Random</button>
                        </td>
                    </tr>
                    <tr>
                        <th><label for="new_client_redirect_uris">Redirect URIs</label></th>
                        <td>
                            <textarea id="new_client_redirect_uris" class="large-text" rows="3" placeholder="http://localhost:3000/callback&#10;https://myapp.com/callback"></textarea>
                            <p class="description">One redirect URI per line. These must match exactly what your application sends.</p>
                        </td>
                    </tr>
                </table>
                <button type="button" id="add_oauth2_client" class="button button-primary">Add OAuth2 Client</button>
            </div>

            <div class="oauth2-existing-clients">
                <h3>Existing OAuth2 Clients</h3>
                <?php if (empty($clients)): ?>
                    <p>No OAuth2 clients configured yet.</p>
                <?php else: ?>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th>Client Name</th>
                                <th>Client ID</th>
                                <th>Redirect URIs</th>
                                <th>Created</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($clients as $client_id => $client): ?>
                                <tr>
                                    <td><?php echo esc_html($client['name'] ?? 'Unnamed Client'); ?></td>
                                    <td><code><?php echo esc_html($client_id); ?></code></td>
                                    <td>
                                        <?php
                                        $uris = $client['redirect_uris'] ?? [];
                                        foreach (array_slice($uris, 0, 3) as $uri) {
                                            echo '<code>' . esc_html($uri) . '</code><br>';
                                        }
                                        if (count($uris) > 3) {
                                            echo '<em>... and ' . (count($uris) - 3) . ' more</em>';
                                        }
                                        ?>
                                    </td>
                                    <td><?php echo esc_html($client['created_at'] ?? 'Unknown'); ?></td>
                                    <td>
                                        <button type="button" class="button delete-client" data-client-id="<?php echo esc_attr($client_id); ?>">Delete</button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <div class="oauth2-scopes-info">
                <h3>Available OAuth2 Scopes</h3>
                <p>These scopes can be requested by OAuth2 clients:</p>
                <ul>
                    <?php foreach (wp_auth_oauth2_get_available_scopes() as $scope => $description): ?>
                        <li><code><?php echo esc_html($scope); ?></code> - <?php echo esc_html($description); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>

        <script>
        jQuery(document).ready(function($) {
            $('#generate_client_id').click(function() {
                const chars = 'abcdefghijklmnopqrstuvwxyz0123456789-';
                let clientId = '';
                for (let i = 0; i < 16; i++) {
                    clientId += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                $('#new_client_id').val(clientId);
            });

            $('#add_oauth2_client').click(function() {
                const name = $('#new_client_name').val();
                const clientId = $('#new_client_id').val();
                const redirectUris = $('#new_client_redirect_uris').val();

                if (!name || !clientId || !redirectUris) {
                    alert('All fields are required.');
                    return;
                }

                $.post(wpRestAuthOAuth2.ajaxUrl, {
                    action: 'add_oauth2_client',
                    name: name,
                    client_id: clientId,
                    redirect_uris: redirectUris,
                    nonce: wpRestAuthOAuth2.nonce
                }, function(response) {
                    if (response.success) {
                        location.reload();
                    } else {
                        alert('Error: ' + response.data);
                    }
                });
            });

            $('.delete-client').click(function() {
                const clientId = $(this).data('client-id');
                if (confirm('Are you sure you want to delete this OAuth2 client?')) {
                    $.post(wpRestAuthOAuth2.ajaxUrl, {
                        action: 'delete_oauth2_client',
                        client_id: clientId,
                        nonce: wpRestAuthOAuth2.nonce
                    }, function(response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            alert('Error: ' + response.data);
                        }
                    });
                }
            });
        });
        </script>
        <?php
    }

    private function render_help_tab() {
        ?>
        <div class="help-tab">
            <h2>Help & Documentation</h2>

            <div class="help-section">
                <h3>🔑 OAuth2 Authentication</h3>
                <p><strong>What is OAuth2:</strong> An authorization framework that enables applications to obtain limited access to user accounts. It works by delegating user authentication to the service that hosts the user account, and authorizing third-party applications to access the user account.</p>

                <h4>OAuth2 Authorization Code Flow:</h4>
                <ol>
                    <li><strong>Authorization Request:</strong> Client redirects user to WordPress authorization endpoint</li>
                    <li><strong>User Authorization:</strong> User logs in and grants/denies permission</li>
                    <li><strong>Authorization Code:</strong> WordPress redirects back to client with authorization code</li>
                    <li><strong>Access Token:</strong> Client exchanges code for access token (backend)</li>
                    <li><strong>API Calls:</strong> Client uses access token to make authenticated requests</li>
                </ol>

                <h4>Available OAuth2 Scopes:</h4>
                <ul>
                    <?php foreach (wp_auth_oauth2_get_available_scopes() as $scope => $description): ?>
                        <li><code><?php echo esc_html($scope); ?></code> - <?php echo esc_html($description); ?></li>
                    <?php endforeach; ?>
                </ul>

                <h4>OAuth2 Endpoints:</h4>
                <ul>
                    <li><code>GET /wp-json/oauth2/v1/authorize</code> - Authorization endpoint</li>
                    <li><code>POST /wp-json/oauth2/v1/token</code> - Token endpoint</li>
                    <li><code>GET /wp-json/oauth2/v1/userinfo</code> - User information endpoint</li>
                    <li><code>POST /wp-json/oauth2/v1/refresh</code> - Refresh token endpoint</li>
                    <li><code>POST /wp-json/oauth2/v1/logout</code> - Logout endpoint</li>
                </ul>
            </div>

            <div class="help-section">
                <h3>⚙️ Configuration</h3>
                <p><strong>OAuth2 Clients:</strong> Applications that can request authorization from your WordPress site.</p>
                <p><strong>Redirect URIs:</strong> Allowed URLs where users will be redirected after authorization.</p>
                <p><strong>CORS Origins:</strong> Domains allowed to make cross-origin requests to your API.</p>
            </div>

            <div class="help-section">
                <h3>🔧 Troubleshooting</h3>
                <h4>Common Issues:</h4>
                <ul>
                    <li><strong>OAuth2 Redirect URI Mismatch:</strong> Ensure redirect URIs match exactly (including protocol and port)</li>
                    <li><strong>Invalid Client:</strong> Check that client ID and secret are correct</li>
                    <li><strong>Scope Errors:</strong> User may not have required capabilities for requested scopes</li>
                    <li><strong>CORS Errors:</strong> Add your frontend domain to the CORS allowed origins</li>
                    <li><strong>Token Expired:</strong> Implement proper token refresh logic in your application</li>
                </ul>

                <h4>Debug Information:</h4>
                <p><strong>Plugin Version:</strong> <?php echo esc_html(WP_REST_AUTH_OAUTH2_VERSION); ?></p>
                <p><strong>WordPress Version:</strong> <?php echo esc_html(get_bloginfo('version')); ?></p>
                <p><strong>PHP Version:</strong> <?php echo esc_html(PHP_VERSION); ?></p>
                <p><strong>SSL Enabled:</strong> <?php echo is_ssl() ? '✅ Yes' : '❌ No (Required for production OAuth2)'; ?></p>
            </div>

        </div>
        <?php
    }

    // Section callbacks
    public function general_settings_section() {
        echo '<p>General plugin settings and security options for OAuth2 authentication.</p>';
    }

    // Field callbacks
    public function enable_debug_logging_field() {
        $settings = get_option(self::OPTION_GENERAL_SETTINGS, []);
        $checked = isset($settings['enable_debug_logging']) && $settings['enable_debug_logging'];
        ?>
        <label>
            <input type="checkbox" name="<?php echo self::OPTION_GENERAL_SETTINGS; ?>[enable_debug_logging]" value="1" <?php checked($checked); ?> />
            Enable detailed logging for OAuth2 authentication events
        </label>
        <p class="description">Logs will be written to your WordPress debug log. Ensure WP_DEBUG_LOG is enabled.</p>
        <?php
    }

    public function cors_allowed_origins_field() {
        $settings = get_option(self::OPTION_GENERAL_SETTINGS, []);
        $value = $settings['cors_allowed_origins'] ?? "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175\nhttps://example.com";
        ?>
        <textarea name="<?php echo self::OPTION_GENERAL_SETTINGS; ?>[cors_allowed_origins]" class="large-text" rows="5"><?php echo esc_textarea($value); ?></textarea>
        <p class="description">One origin per line. Use * to allow all origins (not recommended for production).</p>
        <?php
    }

    // Sanitization callbacks
    public function sanitize_oauth2_settings($input) {
        return $input; // OAuth2 settings are managed via AJAX
    }

    public function sanitize_general_settings($input) {
        $sanitized = [];

        $sanitized['enable_debug_logging'] = isset($input['enable_debug_logging']) && $input['enable_debug_logging'];

        if (isset($input['cors_allowed_origins'])) {
            $origins = sanitize_textarea_field($input['cors_allowed_origins']);
            $sanitized['cors_allowed_origins'] = $origins;
        }

        return $sanitized;
    }

    // AJAX handlers
    public function ajax_add_oauth2_client() {
        if (!wp_verify_nonce($_POST['nonce'], 'wp_rest_auth_oauth2_nonce')) {
            wp_die('Invalid nonce');
        }

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        $name = sanitize_text_field($_POST['name']);
        $client_id = wp_auth_oauth2_sanitize_client_id($_POST['client_id']);
        $redirect_uris = array_filter(array_map('esc_url_raw', array_map('trim', explode("\n", $_POST['redirect_uris']))));

        if (empty($name) || empty($client_id) || empty($redirect_uris)) {
            wp_send_json_error('All fields are required.');
        }

        // Validate redirect URIs
        foreach ($redirect_uris as $uri) {
            if (!wp_auth_oauth2_validate_redirect_uri($uri)) {
                wp_send_json_error('Invalid redirect URI: ' . $uri);
            }
        }

        $oauth2_settings = get_option(self::OPTION_OAUTH2_SETTINGS, []);
        $clients = $oauth2_settings['clients'] ?? [];

        if (isset($clients[$client_id])) {
            wp_send_json_error('Client ID already exists.');
        }

        $clients[$client_id] = [
            'name' => $name,
            'client_secret' => wp_hash_password(wp_generate_password(32, false)),
            'redirect_uris' => $redirect_uris,
            'created_at' => current_time('mysql')
        ];

        $oauth2_settings['clients'] = $clients;
        update_option(self::OPTION_OAUTH2_SETTINGS, $oauth2_settings);

        wp_send_json_success('OAuth2 client added successfully.');
    }

    public function ajax_delete_oauth2_client() {
        if (!wp_verify_nonce($_POST['nonce'], 'wp_rest_auth_oauth2_nonce')) {
            wp_die('Invalid nonce');
        }

        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions');
        }

        $client_id = sanitize_text_field($_POST['client_id']);

        $oauth2_settings = get_option(self::OPTION_OAUTH2_SETTINGS, []);
        $clients = $oauth2_settings['clients'] ?? [];

        if (!isset($clients[$client_id])) {
            wp_send_json_error('Client not found.');
        }

        unset($clients[$client_id]);
        $oauth2_settings['clients'] = $clients;
        update_option(self::OPTION_OAUTH2_SETTINGS, $oauth2_settings);

        wp_send_json_success('OAuth2 client deleted successfully.');
    }

    // Cookie configuration methods
    public function cookie_config_section() {
        // Check if OAuth2_Cookie_Config class exists
        if (!class_exists('OAuth2_Cookie_Config')) {
            ?>
            <div class="notice notice-error inline">
                <p><?php esc_html_e('Cookie configuration class not loaded. Please check plugin installation.', 'wp-rest-auth-oauth2'); ?></p>
            </div>
            <?php
            return;
        }

        $environment = OAuth2_Cookie_Config::get_environment();
        $current_config = OAuth2_Cookie_Config::get_config();
        ?>
        <p><?php esc_html_e('Configure cookie security settings for OAuth2 refresh tokens. Settings are automatically configured based on your environment. Use "Auto" to let the plugin detect appropriate settings.', 'wp-rest-auth-oauth2'); ?></p>

        <div class="notice notice-info inline">
            <p>
                <strong><?php esc_html_e('Current Environment:', 'wp-rest-auth-oauth2'); ?></strong>
                <code><?php echo esc_html($environment); ?></code>
            </p>
        </div>

        <div class="notice notice-warning inline">
            <h4><?php esc_html_e('Active Cookie Configuration', 'wp-rest-auth-oauth2'); ?></h4>
            <table class="widefat" style="max-width: 600px;">
                <tbody>
                    <tr>
                        <td><strong><?php esc_html_e('SameSite:', 'wp-rest-auth-oauth2'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['samesite']); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Secure:', 'wp-rest-auth-oauth2'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['secure'] ? 'true' : 'false'); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Path:', 'wp-rest-auth-oauth2'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['path']); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('Domain:', 'wp-rest-auth-oauth2'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['domain'] ?: '(current domain)'); ?></code></td>
                    </tr>
                    <tr>
                        <td><strong><?php esc_html_e('HttpOnly:', 'wp-rest-auth-oauth2'); ?></strong></td>
                        <td><code><?php echo esc_html($current_config['httponly'] ? 'true' : 'false'); ?></code></td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="notice notice-info inline">
            <h4><?php esc_html_e('Environment Detection Logic', 'wp-rest-auth-oauth2'); ?></h4>
            <ul>
                <li><strong><?php esc_html_e('Development:', 'wp-rest-auth-oauth2'); ?></strong>
                    <?php esc_html_e('localhost, *.local, *.test domains OR WP_DEBUG enabled', 'wp-rest-auth-oauth2'); ?>
                </li>
                <li><strong><?php esc_html_e('Staging:', 'wp-rest-auth-oauth2'); ?></strong>
                    <?php esc_html_e('Domains containing "staging", "dev", or "test"', 'wp-rest-auth-oauth2'); ?>
                </li>
                <li><strong><?php esc_html_e('Production:', 'wp-rest-auth-oauth2'); ?></strong>
                    <?php esc_html_e('All other domains', 'wp-rest-auth-oauth2'); ?>
                </li>
            </ul>
        </div>
        <?php
    }

    public function cookie_samesite_field() {
        $defaults = class_exists('OAuth2_Cookie_Config') ? OAuth2_Cookie_Config::get_defaults() : ['samesite' => 'auto'];
        $config = get_option('oauth2_auth_cookie_config', $defaults);
        $value = $config['samesite'] ?? 'auto';
        ?>
        <select name="oauth2_auth_cookie_config[samesite]">
            <option value="auto" <?php selected($value, 'auto'); ?>>
                <?php esc_html_e('Auto (Recommended)', 'wp-rest-auth-oauth2'); ?>
            </option>
            <option value="None" <?php selected($value, 'None'); ?>>
                <?php esc_html_e('None (Cross-site allowed)', 'wp-rest-auth-oauth2'); ?>
            </option>
            <option value="Lax" <?php selected($value, 'Lax'); ?>>
                <?php esc_html_e('Lax (Relaxed)', 'wp-rest-auth-oauth2'); ?>
            </option>
            <option value="Strict" <?php selected($value, 'Strict'); ?>>
                <?php esc_html_e('Strict (Maximum security)', 'wp-rest-auth-oauth2'); ?>
            </option>
        </select>
        <p class="description">
            <?php esc_html_e('Auto: None (development), Lax (staging), Strict (production)', 'wp-rest-auth-oauth2'); ?>
        </p>
        <?php
    }

    public function cookie_secure_field() {
        $defaults = class_exists('OAuth2_Cookie_Config') ? OAuth2_Cookie_Config::get_defaults() : ['secure' => 'auto'];
        $config = get_option('oauth2_auth_cookie_config', $defaults);
        $value = $config['secure'] ?? 'auto';
        ?>
        <select name="oauth2_auth_cookie_config[secure]">
            <option value="auto" <?php selected($value, 'auto'); ?>>
                <?php esc_html_e('Auto (Recommended)', 'wp-rest-auth-oauth2'); ?>
            </option>
            <option value="1" <?php selected($value, '1'); ?>>
                <?php esc_html_e('Enabled (HTTPS required)', 'wp-rest-auth-oauth2'); ?>
            </option>
            <option value="0" <?php selected($value, '0'); ?>>
                <?php esc_html_e('Disabled (HTTP allowed)', 'wp-rest-auth-oauth2'); ?>
            </option>
        </select>
        <p class="description">
            <?php esc_html_e('Auto: Enabled for staging/production, disabled for development without HTTPS', 'wp-rest-auth-oauth2'); ?>
        </p>
        <?php
    }

    public function cookie_path_field() {
        $defaults = class_exists('OAuth2_Cookie_Config') ? OAuth2_Cookie_Config::get_defaults() : ['path' => 'auto'];
        $config = get_option('oauth2_auth_cookie_config', $defaults);
        $value = $config['path'] ?? 'auto';
        ?>
        <input type="text"
            name="oauth2_auth_cookie_config[path]"
            value="<?php echo esc_attr($value); ?>"
            class="regular-text"
            placeholder="auto"
        />
        <p class="description">
            <?php esc_html_e('Auto: "/" (development), "/wp-json/oauth2/v1/" (staging/production)', 'wp-rest-auth-oauth2'); ?>
        </p>
        <?php
    }

    public function cookie_domain_field() {
        $defaults = class_exists('OAuth2_Cookie_Config') ? OAuth2_Cookie_Config::get_defaults() : ['domain' => 'auto'];
        $config = get_option('oauth2_auth_cookie_config', $defaults);
        $value = $config['domain'] ?? 'auto';
        ?>
        <input type="text"
            name="oauth2_auth_cookie_config[domain]"
            value="<?php echo esc_attr($value); ?>"
            class="regular-text"
            placeholder="auto"
        />
        <p class="description">
            <?php esc_html_e('Auto: Empty (current domain only). Use for subdomain sharing (e.g., ".example.com")', 'wp-rest-auth-oauth2'); ?>
        </p>
        <?php
    }

    public function sanitize_cookie_settings($input) {
        // Get existing settings or defaults
        $defaults = class_exists('OAuth2_Cookie_Config') ? OAuth2_Cookie_Config::get_defaults() : [
            'samesite' => 'auto',
            'secure' => 'auto',
            'path' => 'auto',
            'domain' => 'auto',
        ];
        $existing = get_option('oauth2_auth_cookie_config', $defaults);

        // Handle null or invalid input - return existing settings
        if (!is_array($input)) {
            return $existing;
        }

        // Start with existing settings to preserve all fields
        $sanitized = $existing;

        // Sanitize SameSite
        if (isset($input['samesite'])) {
            $valid_samesite = ['auto', 'None', 'Lax', 'Strict'];
            $sanitized['samesite'] = in_array($input['samesite'], $valid_samesite, true) ? $input['samesite'] : 'auto';
        }

        // Sanitize Secure
        if (isset($input['secure'])) {
            if ('auto' === $input['secure']) {
                $sanitized['secure'] = 'auto';
            } else {
                $sanitized['secure'] = in_array($input['secure'], ['1', 1, true], true) ? '1' : '0';
            }
        }

        // Sanitize Path
        if (isset($input['path'])) {
            $sanitized['path'] = 'auto' === $input['path'] ? 'auto' : sanitize_text_field($input['path']);
        }

        // Sanitize Domain
        if (isset($input['domain'])) {
            $sanitized['domain'] = 'auto' === $input['domain'] ? 'auto' : sanitize_text_field($input['domain']);
        }

        // Clear cache after saving (if class exists)
        if (class_exists('OAuth2_Cookie_Config') && method_exists('OAuth2_Cookie_Config', 'clear_cache')) {
            OAuth2_Cookie_Config::clear_cache();
        }

        return $sanitized;
    }

    // Helper methods to get settings
    public static function get_oauth2_settings() {
        return get_option(self::OPTION_OAUTH2_SETTINGS, [
            'clients' => []
        ]);
    }

    public static function get_general_settings() {
        return get_option(self::OPTION_GENERAL_SETTINGS, [
            'enable_debug_logging' => false,
            'cors_allowed_origins' => "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175\nhttps://example.com"
        ]);
    }
}