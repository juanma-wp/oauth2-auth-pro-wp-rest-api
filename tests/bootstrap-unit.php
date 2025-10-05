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

if ( ! function_exists( 'wp_auth_oauth2_generate_refresh_token' ) ) {
	function wp_auth_oauth2_generate_refresh_token() {
		return 'refresh_' . bin2hex( random_bytes( 32 ) );
	}
}

if ( ! function_exists( 'wp_auth_oauth2_validate_scope' ) ) {
	function wp_auth_oauth2_validate_scope( $scope ) {
		$valid_scopes = array( 'read', 'write', 'edit', 'delete', 'profile' );
		return in_array( $scope, $valid_scopes, true );
	}
}
