<?php
/**
 * Admin Settings for WP REST Auth OAuth2
 * Configuration for OAuth2 authentication
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WPRestAuth\AuthToolkit\Admin\BaseAdminSettings;

/**
 * Admin Settings for OAuth2 Authentication
 *
 * Manages WordPress admin interface for OAuth2 client configuration,
 * general settings, and cookie settings.
 */
class WP_REST_Auth_OAuth2_Admin_Settings extends BaseAdminSettings {

	const OPTION_GROUP            = 'wp_rest_auth_oauth2_settings';
	const OPTION_OAUTH2_SETTINGS  = 'wp_rest_auth_oauth2_settings';
	const OPTION_GENERAL_SETTINGS = 'wp_rest_auth_oauth2_general_settings';

	/**
	 * Get the option group name
	 */
	protected function getOptionGroup(): string {
		return self::OPTION_GROUP;
	}

	/**
	 * Get the general settings option name
	 */
	protected function getGeneralSettingsOption(): string {
		return self::OPTION_GENERAL_SETTINGS;
	}

	/**
	 * Get the cookie settings option name
	 */
	protected function getCookieSettingsOption(): string {
		return 'oauth2_auth_cookie_config';
	}

	/**
	 * Get the settings page slug
	 */
	protected function getPageSlug(): string {
		return 'wp-rest-auth-oauth2';
	}

	/**
	 * Get the cookie config class name
	 */
	protected function getCookieConfigClass(): string {
		return 'OAuth2_Cookie_Config';
	}

	/**
	 * Constructor
	 *
	 * Registers admin menu, settings, scripts, and AJAX handlers.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );

		// AJAX handlers for OAuth2 client management.
		add_action( 'wp_ajax_add_oauth2_client', array( $this, 'ajax_add_oauth2_client' ) );
		add_action( 'wp_ajax_delete_oauth2_client', array( $this, 'ajax_delete_oauth2_client' ) );
	}

	/**
	 * Add admin menu
	 *
	 * Registers OAuth2 settings page under WordPress Settings menu.
	 *
	 * @return void
	 */
	public function add_admin_menu() {
		add_options_page(
			'WP REST Auth OAuth2 Settings',
			'WP REST Auth OAuth2',
			'manage_options',
			'wp-rest-auth-oauth2',
			array( $this, 'admin_page' )
		);
	}

	/**
	 * Register plugin settings
	 *
	 * Registers OAuth2, general, and cookie settings with WordPress settings API.
	 *
	 * @return void
	 */
	public function register_settings() {
		// Register OAuth2 settings.
		register_setting(
			self::OPTION_GROUP,
			self::OPTION_OAUTH2_SETTINGS,
			array(
				'sanitize_callback' => array( $this, 'sanitize_oauth2_settings' ),
			)
		);

		// Register General Settings and Cookie Settings using base class.
		$this->registerGeneralSettings( 'wp-rest-auth-oauth2-general' );
		$this->registerCookieSettings( 'wp-rest-auth-oauth2-cookies' );
	}

	/**
	 * Enqueue admin scripts
	 *
	 * Loads JavaScript and localized data for OAuth2 admin interface.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function enqueue_admin_scripts( $hook ) {
		if ( 'settings_page_wp-rest-auth-oauth2' !== $hook ) {
			return;
		}

		wp_enqueue_script(
			'wp-rest-auth-oauth2-admin',
			plugin_dir_url( __DIR__ ) . 'assets/admin.js',
			array( 'jquery' ),
			'1.0.0',
			true
		);

		wp_localize_script(
			'wp-rest-auth-oauth2-admin',
			'wpRestAuthOAuth2',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'wp_rest_auth_oauth2_nonce' ),
			)
		);
	}

	/**
	 * Render admin page
	 *
	 * Displays tabbed interface for OAuth2, general, cookie settings, and help.
	 *
	 * @return void
	 */
	public function admin_page() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$active_tab = $_GET['tab'] ?? 'oauth2';
		?>
		<div class="wrap">
			<h1>🔐 WP REST Auth OAuth2 Settings</h1>
			<p class="description">OAuth2 authentication for WordPress REST API</p>

			<nav class="nav-tab-wrapper">
				<a href="?page=wp-rest-auth-oauth2&tab=oauth2" class="nav-tab <?php echo 'oauth2' === $active_tab ? 'nav-tab-active' : ''; ?>">OAuth2 Settings</a>
				<a href="?page=wp-rest-auth-oauth2&tab=general" class="nav-tab <?php echo 'general' === $active_tab ? 'nav-tab-active' : ''; ?>">General Settings</a>
				<a href="?page=wp-rest-auth-oauth2&tab=cookies" class="nav-tab <?php echo 'cookies' === $active_tab ? 'nav-tab-active' : ''; ?>">Cookie Settings</a>
				<a href="?page=wp-rest-auth-oauth2&tab=help" class="nav-tab <?php echo 'help' === $active_tab ? 'nav-tab-active' : ''; ?>">Help & Documentation</a>
			</nav>

			<?php if ( 'help' === $active_tab ) : ?>
				<?php $this->render_help_tab(); ?>
			<?php else : ?>
				<form method="post" action="options.php">
					<?php
					settings_fields( self::OPTION_GROUP );

					if ( 'oauth2' === $active_tab ) {
						$this->render_oauth2_tab();
					} elseif ( 'general' === $active_tab ) {
						do_settings_sections( 'wp-rest-auth-oauth2-general' );
						submit_button();
					} elseif ( 'cookies' === $active_tab ) {
						do_settings_sections( 'wp-rest-auth-oauth2-cookies' );
						// No submit button - read-only display.
					}
					?>
				</form>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Override cookie config section to show read-only display like JWT plugin
	 */
	public function cookieConfigSection(): void {
		if ( ! class_exists( 'OAuth2_Cookie_Config' ) ) {
			?>
			<div class="notice notice-error inline">
				<p><?php esc_html_e( 'Cookie configuration class not loaded. Please check plugin installation.', 'wp-rest-auth-oauth2' ); ?></p>
			</div>
			<?php
			return;
		}

		$environment    = OAuth2_Cookie_Config::get_environment();
		$current_config = OAuth2_Cookie_Config::get_config();
		?>
		<p style="font-size: 14px; line-height: 1.6;">
			<?php esc_html_e( 'Cookie security settings are automatically configured based on your environment. Configuration can be customized using constants or filters.', 'wp-rest-auth-oauth2' ); ?>
		</p>

		<!-- Detected Environment -->
		<div class="notice notice-info inline" style="margin: 20px 0 15px 0;">
			<h3 style="margin: 0 0 10px 0;">🌍 <?php esc_html_e( 'Detected Environment', 'wp-rest-auth-oauth2' ); ?></h3>
			<p style="font-size: 16px; margin: 5px 0;">
				<code style="font-size: 15px; padding: 5px 10px; background: #fff; border-radius: 3px; font-weight: bold;">
					<?php echo esc_html( ucfirst( $environment ) ); ?>
				</code>
			</p>
			<p class="description" style="margin-top: 8px;">
				<?php
				switch ( $environment ) {
					case 'development':
						esc_html_e( 'Detected via: localhost, *.local, *.test domains, or WP_DEBUG=true', 'wp-rest-auth-oauth2' );
						break;
					case 'staging':
						esc_html_e( 'Detected via: domain contains "staging", "dev", or "test"', 'wp-rest-auth-oauth2' );
						break;
					case 'production':
						esc_html_e( 'Detected via: standard production domain', 'wp-rest-auth-oauth2' );
						break;
				}
				?>
			</p>
		</div>

		<!-- Active Cookie Configuration -->
		<div class="notice notice-success inline" style="margin: 15px 0;">
			<h3 style="margin: 0 0 10px 0;">🍪 <?php esc_html_e( 'Active Cookie Configuration', 'wp-rest-auth-oauth2' ); ?></h3>
			<table class="widefat striped" style="max-width: 100%; margin-top: 10px;">
				<thead>
					<tr>
						<th style="width: 25%;"><?php esc_html_e( 'Setting', 'wp-rest-auth-oauth2' ); ?></th>
						<th style="width: 20%;"><?php esc_html_e( 'Value', 'wp-rest-auth-oauth2' ); ?></th>
						<th><?php esc_html_e( 'Description', 'wp-rest-auth-oauth2' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><strong><?php esc_html_e( 'Cookie Name', 'wp-rest-auth-oauth2' ); ?></strong></td>
						<td><code><?php echo esc_html( $current_config['name'] ); ?></code></td>
						<td><?php esc_html_e( 'Name of the HTTP-only cookie storing the refresh token', 'wp-rest-auth-oauth2' ); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'SameSite', 'wp-rest-auth-oauth2' ); ?></strong></td>
						<td><code><?php echo esc_html( $current_config['samesite'] ); ?></code></td>
						<td>
							<?php
							if ( 'None' === $current_config['samesite'] ) {
								esc_html_e( 'Cross-origin allowed (for SPAs on different domains)', 'wp-rest-auth-oauth2' );
							} elseif ( 'Lax' === $current_config['samesite'] ) {
								esc_html_e( 'Relaxed protection, top-level navigation allowed', 'wp-rest-auth-oauth2' );
							} else {
								esc_html_e( 'Strict protection, same-origin requests only', 'wp-rest-auth-oauth2' );
							}
							?>
						</td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Secure', 'wp-rest-auth-oauth2' ); ?></strong></td>
						<td><code><?php echo esc_html( $current_config['secure'] ? 'true' : 'false' ); ?></code></td>
						<td><?php echo esc_html( $current_config['secure'] ? __( 'Cookie only sent over HTTPS', 'wp-rest-auth-oauth2' ) : __( 'Cookie sent over HTTP (⚠️ not recommended for production)', 'wp-rest-auth-oauth2' ) ); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'HttpOnly', 'wp-rest-auth-oauth2' ); ?></strong></td>
						<td><code><?php echo esc_html( $current_config['httponly'] ? 'true' : 'false' ); ?></code></td>
						<td><?php esc_html_e( 'Cookie not accessible via JavaScript (XSS protection)', 'wp-rest-auth-oauth2' ); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Path', 'wp-rest-auth-oauth2' ); ?></strong></td>
						<td><code><?php echo esc_html( $current_config['path'] ); ?></code></td>
						<td><?php esc_html_e( 'URL path scope where cookie is valid', 'wp-rest-auth-oauth2' ); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Domain', 'wp-rest-auth-oauth2' ); ?></strong></td>
						<td><code><?php echo esc_html( $current_config['domain'] ? $current_config['domain'] : '(current domain)' ); ?></code></td>
						<td><?php esc_html_e( 'Domain scope where cookie is valid', 'wp-rest-auth-oauth2' ); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Lifetime', 'wp-rest-auth-oauth2' ); ?></strong></td>
						<td><code><?php echo esc_html( human_time_diff( 0, $current_config['lifetime'] ) ); ?></code></td>
						<td><?php esc_html_e( 'Duration the refresh token remains valid', 'wp-rest-auth-oauth2' ); ?></td>
					</tr>
				</tbody>
			</table>
		</div>

		<!-- Configuration Priority -->
		<div class="notice notice-info inline" style="margin: 15px 0;">
			<h3 style="margin: 0 0 10px 0;">⚙️ <?php esc_html_e( 'Configuration Priority', 'wp-rest-auth-oauth2' ); ?></h3>
			<p><?php esc_html_e( 'Settings are applied in the following order (highest to lowest priority):', 'wp-rest-auth-oauth2' ); ?></p>
			<ol style="line-height: 2.2; margin: 10px 0 10px 20px;">
				<li>
					<strong><?php esc_html_e( 'Constants', 'wp-rest-auth-oauth2' ); ?></strong>
					<code style="font-size: 12px; background: #f0f0f0; padding: 2px 6px; border-radius: 3px;">OAUTH2_AUTH_COOKIE_*</code>
					<em class="description"> — <?php esc_html_e( 'in wp-config.php', 'wp-rest-auth-oauth2' ); ?></em>
				</li>
				<li>
					<strong><?php esc_html_e( 'Filters', 'wp-rest-auth-oauth2' ); ?></strong>
					<code style="font-size: 12px; background: #f0f0f0; padding: 2px 6px; border-radius: 3px;">oauth2_auth_cookie_*</code>
					<em class="description"> — <?php esc_html_e( 'in theme/plugin code', 'wp-rest-auth-oauth2' ); ?></em>
				</li>
				<li>
					<strong><?php esc_html_e( 'Environment Defaults', 'wp-rest-auth-oauth2' ); ?></strong>
					<em class="description"> — <?php esc_html_e( 'auto-detected based on environment', 'wp-rest-auth-oauth2' ); ?></em>
				</li>
				<li>
					<strong><?php esc_html_e( 'Hard-coded Defaults', 'wp-rest-auth-oauth2' ); ?></strong>
					<em class="description"> — <?php esc_html_e( 'fallback values', 'wp-rest-auth-oauth2' ); ?></em>
				</li>
			</ol>
		</div>
		<?php
	}

	/**
	 * Render OAuth2 settings tab
	 *
	 * Displays OAuth2 client management interface.
	 *
	 * @return void
	 */
	private function render_oauth2_tab() {
		$oauth2_settings = get_option( self::OPTION_OAUTH2_SETTINGS, array() );
		$clients         = $oauth2_settings['clients'] ?? array();
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
				<?php if ( empty( $clients ) ) : ?>
					<p>No OAuth2 clients configured yet.</p>
				<?php else : ?>
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
							<?php foreach ( $clients as $client_id => $client ) : ?>
								<tr>
									<td><?php echo esc_html( $client['name'] ?? 'Unnamed Client' ); ?></td>
									<td><code><?php echo esc_html( $client_id ); ?></code></td>
									<td>
										<?php
										$uris = $client['redirect_uris'] ?? array();
										foreach ( array_slice( $uris, 0, 3 ) as $uri ) {
											echo '<code>' . esc_html( $uri ) . '</code><br>';
										}
										if ( count( $uris ) > 3 ) {
											echo '<em>... and ' . ( count( $uris ) - 3 ) . ' more</em>';
										}
										?>
									</td>
									<td><?php echo esc_html( $client['created_at'] ?? 'Unknown' ); ?></td>
									<td>
										<button type="button" class="button delete-client" data-client-id="<?php echo esc_attr( $client_id ); ?>">Delete</button>
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
					<?php foreach ( wp_auth_oauth2_get_available_scopes() as $scope => $description ) : ?>
						<li><code><?php echo esc_html( $scope ); ?></code> - <?php echo esc_html( $description ); ?></li>
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

	/**
	 * Render help tab
	 *
	 * Displays OAuth2 documentation and troubleshooting information.
	 *
	 * @return void
	 */
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
					<?php foreach ( wp_auth_oauth2_get_available_scopes() as $scope => $description ) : ?>
						<li><code><?php echo esc_html( $scope ); ?></code> - <?php echo esc_html( $description ); ?></li>
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
				<p><strong>Plugin Version:</strong> <?php echo esc_html( WP_REST_AUTH_OAUTH2_VERSION ); ?></p>
				<p><strong>WordPress Version:</strong> <?php echo esc_html( get_bloginfo( 'version' ) ); ?></p>
				<p><strong>PHP Version:</strong> <?php echo esc_html( PHP_VERSION ); ?></p>
				<p><strong>SSL Enabled:</strong> <?php echo is_ssl() ? '✅ Yes' : '❌ No (Required for production OAuth2)'; ?></p>
			</div>

		</div>
		<?php
	}

	/**
	 * Sanitize OAuth2 settings
	 *
	 * OAuth2 settings are managed via AJAX handlers, so this returns input unchanged.
	 *
	 * @param array $input Settings input.
	 * @return array Sanitized settings.
	 */
	public function sanitize_oauth2_settings( $input ) {
		return $input;
	}

	/**
	 * AJAX handler to add OAuth2 client
	 *
	 * Validates and creates a new OAuth2 client with generated credentials.
	 *
	 * @return void
	 */
	public function ajax_add_oauth2_client() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! wp_verify_nonce( $_POST['nonce'], 'wp_rest_auth_oauth2_nonce' ) ) {
			wp_die( 'Invalid nonce' );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions' );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$name = sanitize_text_field( $_POST['name'] );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$client_id = wp_auth_oauth2_sanitize_client_id( $_POST['client_id'] );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$redirect_uris = array_filter( array_map( 'esc_url_raw', array_map( 'trim', explode( "\n", $_POST['redirect_uris'] ) ) ) );

		if ( empty( $name ) || empty( $client_id ) || empty( $redirect_uris ) ) {
			wp_send_json_error( 'All fields are required.' );
		}

		// Validate redirect URIs.
		foreach ( $redirect_uris as $uri ) {
			if ( ! wp_auth_oauth2_validate_redirect_uri( $uri ) ) {
				wp_send_json_error( 'Invalid redirect URI: ' . $uri );
			}
		}

		$oauth2_settings = get_option( self::OPTION_OAUTH2_SETTINGS, array() );
		$clients         = $oauth2_settings['clients'] ?? array();

		if ( isset( $clients[ $client_id ] ) ) {
			wp_send_json_error( 'Client ID already exists.' );
		}

		$clients[ $client_id ] = array(
			'name'          => $name,
			'client_secret' => wp_hash_password( wp_generate_password( 32, false ) ),
			'redirect_uris' => $redirect_uris,
			'created_at'    => current_time( 'mysql' ),
		);

		$oauth2_settings['clients'] = $clients;
		update_option( self::OPTION_OAUTH2_SETTINGS, $oauth2_settings );

		wp_send_json_success( 'OAuth2 client added successfully.' );
	}

	/**
	 * AJAX handler to delete OAuth2 client
	 *
	 * Removes an existing OAuth2 client and its credentials.
	 *
	 * @return void
	 */
	public function ajax_delete_oauth2_client() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! wp_verify_nonce( $_POST['nonce'], 'wp_rest_auth_oauth2_nonce' ) ) {
			wp_die( 'Invalid nonce' );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Insufficient permissions' );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$client_id = sanitize_text_field( $_POST['client_id'] );

		$oauth2_settings = get_option( self::OPTION_OAUTH2_SETTINGS, array() );
		$clients         = $oauth2_settings['clients'] ?? array();

		if ( ! isset( $clients[ $client_id ] ) ) {
			wp_send_json_error( 'Client not found.' );
		}

		unset( $clients[ $client_id ] );
		$oauth2_settings['clients'] = $clients;
		update_option( self::OPTION_OAUTH2_SETTINGS, $oauth2_settings );

		wp_send_json_success( 'OAuth2 client deleted successfully.' );
	}

	/**
	 * Get OAuth2 settings
	 *
	 * @return array OAuth2 settings with clients array.
	 */
	public static function get_oauth2_settings() {
		return get_option(
			self::OPTION_OAUTH2_SETTINGS,
			array(
				'clients' => array(),
			)
		);
	}

	/**
	 * Get general settings
	 *
	 * @return array General settings with default values.
	 */
	public static function get_general_settings() {
		return get_option(
			self::OPTION_GENERAL_SETTINGS,
			array(
				'enable_debug_logging' => false,
				'cors_allowed_origins' => "http://localhost:3000\nhttp://localhost:5173\nhttp://localhost:5174\nhttp://localhost:5175",
			)
		);
	}
}
