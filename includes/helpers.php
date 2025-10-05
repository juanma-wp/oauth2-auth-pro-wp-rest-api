<?php
/**
 * Helper functions for WP REST Auth OAuth2
 * Utilities for OAuth2 authentication
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WPRestAuth\AuthToolkit\Token\Generator;
use WPRestAuth\AuthToolkit\Token\Hasher;
use WPRestAuth\AuthToolkit\Token\RefreshTokenManager;
use WPRestAuth\AuthToolkit\Security\IpResolver;
use WPRestAuth\AuthToolkit\Security\UserAgent;
use WPRestAuth\AuthToolkit\Http\Cookie;
use WPRestAuth\AuthToolkit\Http\Cors;
use WPRestAuth\AuthToolkit\Http\Response;
use WPRestAuth\AuthToolkit\OAuth2\Pkce;
use WPRestAuth\AuthToolkit\OAuth2\Scope;

/**
 * Generate a secure random token
 *
 * @param int $length Token length in bytes.
 * @return string Generated token.
 */
function wp_auth_oauth2_generate_token( int $length = 64 ): string {
	return Generator::generate( $length );
}

/**
 * Hash a token for database storage
 *
 * @param string $token  Token to hash.
 * @param string $secret Secret key for hashing.
 * @return string Hashed token.
 */
function wp_auth_oauth2_hash_token( string $token, string $secret ): string {
	return Hasher::make( $token, $secret );
}

/**
 * Get client IP address
 */
function wp_auth_oauth2_get_ip_address(): string {
	return IpResolver::get();
}

/**
 * Get user agent
 */
function wp_auth_oauth2_get_user_agent(): string {
	return UserAgent::get();
}

/**
 * Set HTTPOnly cookie
 *
 * @param string    $name     Cookie name.
 * @param string    $value    Cookie value.
 * @param int       $expires  Expiration timestamp.
 * @param string    $path     Cookie path.
 * @param bool      $httponly HTTPOnly flag.
 * @param bool|null $secure   Secure flag (null = auto-detect).
 * @return bool True on success.
 */
function wp_auth_oauth2_set_cookie(
	string $name,
	string $value,
	int $expires,
	string $path = '/',
	bool $httponly = true,
	?bool $secure = null
): bool {
	$options = array(
		'expires'  => $expires,
		'path'     => $path,
		'httponly' => $httponly,
	);

	if ( null !== $secure ) {
		$options['secure'] = $secure;
	}

	return Cookie::set( $name, $value, $options );
}

/**
 * Delete cookie
 *
 * @param string $name Cookie name.
 * @param string $path Cookie path.
 * @return bool True on success.
 */
function wp_auth_oauth2_delete_cookie( string $name, string $path = '/' ): bool {
	return Cookie::delete( $name, $path );
}

/**
 * Check if origin is allowed for CORS
 *
 * @param string $origin Origin to check.
 * @return bool True if allowed.
 */
function wp_auth_oauth2_is_valid_origin( string $origin ): bool {
	$general_settings = WP_REST_Auth_OAuth2_Admin_Settings::get_general_settings();
	$allowed_origins  = $general_settings['cors_allowed_origins'] ?? '';

	if ( empty( $allowed_origins ) ) {
		return false;
	}

	$allowed_list = array_map( 'trim', explode( "\n", $allowed_origins ) );
	$allowed_list = apply_filters( 'wp_auth_oauth2_cors_origins', $allowed_list );

	return in_array( '*', $allowed_list, true ) || in_array( $origin, $allowed_list, true );
}

/**
 * Add CORS headers if needed
 *
 * @return void
 */
function wp_auth_oauth2_maybe_add_cors_headers(): void {
	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
	$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

	if ( $origin && wp_auth_oauth2_is_valid_origin( $origin ) ) {
		header( 'Access-Control-Allow-Origin: ' . $origin );
		header( 'Access-Control-Allow-Credentials: true' );
		header( 'Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH' );
		header( 'Access-Control-Allow-Headers: Authorization, Content-Type, X-Requested-With, X-WP-Nonce' );
		header( 'Access-Control-Max-Age: 86400' );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'OPTIONS' === $_SERVER['REQUEST_METHOD'] ) {
			http_response_code( 200 );
			exit;
		}
	}
}

/**
 * Create success response
 *
 * @param array       $data    Response data.
 * @param string|null $message Optional message.
 * @param int         $status  HTTP status code.
 * @return WP_REST_Response Response object.
 */
function wp_auth_oauth2_success_response( array $data = array(), ?string $message = null, int $status = 200 ): WP_REST_Response {
	$response_data = array(
		'success' => true,
		'data'    => $data,
	);

	if ( $message ) {
		$response_data['message'] = $message;
	}

	return new WP_REST_Response( $response_data, $status );
}

/**
 * Create error response
 *
 * @param string $code    Error code.
 * @param string $message Error message.
 * @param int    $status  HTTP status code.
 * @param array  $data    Additional error data.
 * @return WP_Error Error object.
 */
function wp_auth_oauth2_error_response( string $code, string $message, int $status = 400, array $data = array() ): WP_Error {
	return new WP_Error( $code, $message, array_merge( array( 'status' => $status ), $data ) );
}

/**
 * Format user data for API responses
 *
 * @param WP_User $user              User object.
 * @param bool    $include_sensitive Include sensitive data.
 * @return array Formatted user data.
 */
function wp_auth_oauth2_format_user_data( WP_User $user, bool $include_sensitive = false ): array {
	$user_data = array(
		'id'           => $user->ID,
		'username'     => $user->user_login,
		'email'        => $user->user_email,
		'display_name' => $user->display_name,
		'first_name'   => $user->first_name,
		'last_name'    => $user->last_name,
		'registered'   => $user->user_registered,
		'roles'        => $user->roles,
		'avatar_url'   => get_avatar_url( $user->ID ),
	);

	if ( $include_sensitive ) {
		$user_data['capabilities'] = $user->get_role_caps();
		$user_data['meta']         = array(
			'nickname'    => get_user_meta( $user->ID, 'nickname', true ),
			'description' => get_user_meta( $user->ID, 'description', true ),
		);
	}

	return apply_filters( 'wp_auth_oauth2_user_data', $user_data, $user, $include_sensitive );
}

/**
 * Validate OAuth2 scope format
 *
 * @param string $scope Scope to validate.
 * @return bool True if valid.
 */
function wp_auth_oauth2_validate_scope( string $scope ): bool {
	// OAuth2 scope must be alphanumeric with underscores, colons, and dots.
	return preg_match( '/^[a-zA-Z0-9_:.-]+$/', $scope );
}

/**
 * Parse OAuth2 scopes from string
 *
 * @param string $scope_string Space-separated scopes.
 * @return array Array of valid scopes.
 */
function wp_auth_oauth2_parse_scopes( string $scope_string ): array {
	$scopes = array_filter( array_map( 'trim', explode( ' ', $scope_string ) ) );
	return array_filter( $scopes, 'wp_auth_oauth2_validate_scope' );
}

/**
 * Generate OAuth2 authorization code
 */
function wp_auth_oauth2_generate_auth_code(): string {
	return wp_auth_oauth2_generate_token( 32 );
}

/**
 * Generate OAuth2 access token
 */
function wp_auth_oauth2_generate_access_token(): string {
	return wp_auth_oauth2_generate_token( 48 );
}

/**
 * Generate OAuth2 refresh token
 */
function wp_auth_oauth2_generate_refresh_token(): string {
	return wp_auth_oauth2_generate_token( 64 );
}

/**
 * Sanitize OAuth2 client ID
 *
 * @param string $client_id Client ID to sanitize.
 * @return string Sanitized client ID.
 */
function wp_auth_oauth2_sanitize_client_id( string $client_id ): string {
	// Client ID should be alphanumeric with dashes and underscores.
	return sanitize_key( $client_id );
}

/**
 * Validate redirect URI
 *
 * @param string $uri URI to validate.
 * @return bool True if valid.
 */
function wp_auth_oauth2_validate_redirect_uri( string $uri ): bool {
	$parsed = wp_parse_url( $uri );

	if ( ! $parsed || ! isset( $parsed['scheme'] ) || ! isset( $parsed['host'] ) ) {
		return false;
	}

	// Allow http for localhost development.
	if ( 'localhost' === $parsed['host'] || 0 === strpos( $parsed['host'], '127.0.0.1' ) ) {
		return in_array( $parsed['scheme'], array( 'http', 'https' ), true );
	}

	// Production should use https.
	return 'https' === $parsed['scheme'];
}

/**
 * Get available OAuth2 scopes with descriptions
 *
 * @return array Array of scopes with descriptions.
 */
function wp_auth_oauth2_get_available_scopes(): array {
	$scopes = array(
		'read'              => 'View your posts, pages, and profile information',
		'write'             => 'Create and edit posts and pages',
		'delete'            => 'Delete posts and pages',
		'manage_users'      => 'View and manage user accounts (admin only)',
		'upload_files'      => 'Upload and manage media files',
		'edit_theme'        => 'Modify theme and appearance settings (admin only)',
		'moderate_comments' => 'Moderate and manage comments',
		'view_stats'        => 'Access website statistics and analytics',
		'manage_categories' => 'Create and manage categories and tags',
		'manage_plugins'    => 'Install and manage plugins (admin only)',
		'manage_options'    => 'Modify site settings and options (admin only)',
	);

	return apply_filters( 'wp_auth_oauth2_available_scopes', $scopes );
}

/**
 * Check if user can access specific OAuth2 scope
 *
 * @param WP_User $user  User object.
 * @param string  $scope Scope to check.
 * @return bool True if user can access scope.
 */
function wp_auth_oauth2_user_can_access_scope( WP_User $user, string $scope ): bool {
	$scope_capabilities = array(
		'read'              => 'read',
		'write'             => 'edit_posts',
		'delete'            => 'delete_posts',
		'manage_users'      => 'list_users',
		'upload_files'      => 'upload_files',
		'edit_theme'        => 'edit_theme_options',
		'moderate_comments' => 'moderate_comments',
		'view_stats'        => 'view_query_monitor',
		'manage_categories' => 'manage_categories',
		'manage_plugins'    => 'activate_plugins',
		'manage_options'    => 'manage_options',
	);

	$capability = $scope_capabilities[ $scope ] ?? false;

	if ( ! $capability ) {
		return false;
	}

	return user_can( $user, $capability );
}

/**
 * Log debug information for OAuth2
 *
 * @param string $message Debug message.
 * @param mixed  $data    Optional data to log.
 * @return void
 */
function wp_auth_oauth2_debug_log( string $message, $data = null ): void {
	if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
		$log_message = 'OAuth2 Debug: ' . $message;
		if ( null !== $data ) {
			$log_message .= ' - ' . wp_json_encode( $data );
		}
		error_log( $log_message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
	}
}

/**
 * Get OAuth2 error descriptions
 *
 * @param string $error_code Error code.
 * @return string Error description.
 */
function wp_auth_oauth2_get_error_description( string $error_code ): string {
	$errors = array(
		'invalid_request'           => 'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
		'unauthorized_client'       => 'The client is not authorized to request an authorization code using this method.',
		'access_denied'             => 'The resource owner or authorization server denied the request.',
		'unsupported_response_type' => 'The authorization server does not support obtaining an authorization code using this method.',
		'invalid_scope'             => 'The requested scope is invalid, unknown, or malformed.',
		'server_error'              => 'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
		'temporarily_unavailable'   => 'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
		'invalid_client'            => 'Client authentication failed.',
		'invalid_grant'             => 'The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.',
		'unsupported_grant_type'    => 'The authorization grant type is not supported by the authorization server.',
		'insufficient_scope'        => 'The request requires higher privileges than provided by the access token.',
	);

	return $errors[ $error_code ] ?? 'Unknown error occurred.';
}

/**
 * Create OAuth2 error response with proper format
 *
 * @param string      $error       Error code.
 * @param string|null $description Error description.
 * @param string|null $uri         Error URI.
 * @param string|null $state       State parameter.
 * @return array Error response array.
 */
function wp_auth_oauth2_create_error_response( string $error, ?string $description = null, ?string $uri = null, ?string $state = null ): array {
	$response = array( 'error' => $error );

	if ( $description ) {
		$response['error_description'] = $description;
	} else {
		$response['error_description'] = wp_auth_oauth2_get_error_description( $error );
	}

	if ( $uri ) {
		$response['error_uri'] = $uri;
	}

	if ( $state ) {
		$response['state'] = $state;
	}

	return $response;
}

/**
 * Validate PKCE code challenge method
 *
 * @param string $method Challenge method to validate.
 * @return bool True if valid.
 */
function wp_auth_oauth2_validate_code_challenge_method( string $method ): bool {
	return Pkce::validateMethod( $method );
}

/**
 * Generate PKCE code challenge from verifier
 *
 * @param string $code_verifier The code verifier (43-128 characters).
 * @param string $method        The challenge method ('S256' or 'plain').
 * @return string|false The code challenge, or false on error.
 */
function wp_auth_oauth2_generate_code_challenge( string $code_verifier, string $method = 'S256' ) {
	try {
		return Pkce::generateChallenge( $code_verifier, $method );
	} catch ( \InvalidArgumentException $e ) {
		return false;
	}
}

/**
 * Validate PKCE code verifier format
 * Must be 43-128 characters of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
 *
 * @param string $code_verifier Code verifier to validate.
 * @return bool True if valid.
 */
function wp_auth_oauth2_validate_code_verifier( string $code_verifier ): bool {
	return Pkce::validateVerifier( $code_verifier );
}

/**
 * Verify PKCE code challenge matches verifier
 *
 * @param string $code_verifier  The code verifier provided by client.
 * @param string $code_challenge The stored code challenge.
 * @param string $method         The challenge method used ('S256' or 'plain').
 * @return bool True if verification succeeds.
 */
function wp_auth_oauth2_verify_code_challenge( string $code_verifier, string $code_challenge, string $method = 'S256' ): bool {
	return Pkce::verify( $code_verifier, $code_challenge, $method );
}

/**
 * Apply OAuth2 cookie configuration settings
 * Uses OAuth2_Cookie_Config for environment-aware cookie settings
 */
add_filter(
	'wp_rest_auth_cookie_samesite',
	function ( $samesite ) {
		if ( ! class_exists( 'OAuth2_Cookie_Config' ) ) {
			return $samesite;
		}

		$config = OAuth2_Cookie_Config::get_config();
		return $config['samesite'];
	},
	10,
	1
);

add_filter(
	'wp_rest_auth_cookie_secure',
	function ( $secure ) {
		if ( ! class_exists( 'OAuth2_Cookie_Config' ) ) {
			return $secure;
		}

		$config = OAuth2_Cookie_Config::get_config();
		return $config['secure'];
	},
	10,
	1
);

add_filter(
	'wp_rest_auth_cookie_path',
	function ( $path ) {
		if ( ! class_exists( 'OAuth2_Cookie_Config' ) ) {
			return $path;
		}

		$config = OAuth2_Cookie_Config::get_config();
		return $config['path'];
	},
	10,
	1
);

add_filter(
	'wp_rest_auth_cookie_domain',
	function ( $domain ) {
		if ( ! class_exists( 'OAuth2_Cookie_Config' ) ) {
			return $domain;
		}

		$config = OAuth2_Cookie_Config::get_config();
		return $config['domain'];
	},
	10,
	1
);
