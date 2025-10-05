<?php
/**
 * PHPUnit bootstrap file for unit tests (without WordPress).
 *
 * @package WP_REST_Auth_OAuth2
 */

// Define test constants
if ( ! defined( 'WP_OAUTH2_SECRET' ) ) {
	define( 'WP_OAUTH2_SECRET', 'test-oauth2-secret-key-for-testing-only-never-use-in-production' );
}

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', '/tmp/wordpress/' );
}

// Load Composer autoloader
require_once dirname( __DIR__ ) . '/vendor/autoload.php';

// Mock WordPress functions needed for unit tests
if ( ! function_exists( 'wp_hash_password' ) ) {
	function wp_hash_password( $password ) {
		return password_hash( $password, PASSWORD_BCRYPT );
	}
}

if ( ! function_exists( 'wp_check_password' ) ) {
	function wp_check_password( $password, $hash, $user_id = '' ) {
		return password_verify( $password, $hash );
	}
}

if ( ! function_exists( 'current_time' ) ) {
	function current_time( $type, $gmt = 0 ) {
		if ( 'mysql' === $type ) {
			return gmdate( 'Y-m-d H:i:s' );
		}
		return time();
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
		// Mock implementation - just return true
		return true;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $hook, $value, ...$args ) {
		// Mock implementation - just return the value unchanged
		return $value;
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	function sanitize_key( $key ) {
		// Mock implementation - lowercase and replace non-alphanumeric with dashes
		return strtolower( preg_replace( '/[^a-zA-Z0-9_\-]/', '', $key ) );
	}
}

// Note: OAuth2-specific functions like wp_auth_oauth2_generate_refresh_token()
// and wp_auth_oauth2_validate_scope() are defined in includes/helpers.php
// which will be loaded by the unit tests themselves when needed.
