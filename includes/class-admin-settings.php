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
                <a href="?page=wp-rest-auth-oauth2&tab=help" class="nav-tab <?php echo $active_tab == 'help' ? 'nav-tab-active' : ''; ?>">Help & Documentation</a>
            </nav>

            <form method="post" action="options.php">
                <?php
                settings_fields(self::OPTION_GROUP);

                if ($active_tab == 'oauth2') {
                    $this->render_oauth2_tab();
                } elseif ($active_tab == 'general') {
                    do_settings_sections('wp-rest-auth-oauth2-general');
                    submit_button();
                } elseif ($active_tab == 'help') {
                    $this->render_help_tab();
                }
                ?>
            </form>
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