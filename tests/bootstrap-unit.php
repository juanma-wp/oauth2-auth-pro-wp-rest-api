<?php
/**
 * PHPUnit Bootstrap for Unit Tests
 *
 * This bootstrap file is designed for testing isolated PHP functions without WordPress
 * dependencies. It loads only the minimum required components to test core OAuth2 helper
 * functions and other standalone utilities.
 *
 * Unit tests using this bootstrap should focus on testing individual functions and
 * methods without relying on WordPress core functionality, database connections,
 * or complex integrations.
 *
 * @package WP_REST_Auth_OAuth2
 */

// Load Composer autoloader.
require_once dirname( __DIR__ ) . '/vendor/autoload.php';

// Define minimal constants needed for helpers.php.
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', '/tmp/' );
}

// Mock only essential WordPress functions needed by helpers.php.
if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * Mock wp_json_encode function
	 *
	 * @param mixed $data    Variable to encode.
	 * @param int   $options Optional. Options to be passed to json_encode(). Default 0.
	 * @param int   $depth   Optional. Maximum depth. Default 512.
	 * @return string|false JSON string on success, false on failure.
	 */
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	/**
	 * Mock wp_parse_url function
	 *
	 * @param string $url       The URL to parse.
	 * @param int    $component Optional. Component to retrieve. Default -1.
	 * @return mixed Array or component value on success, false on failure.
	 */
	function wp_parse_url( $url, $component = -1 ) {
		return parse_url( $url, $component );
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Mock sanitize_text_field function
	 *
	 * @param string $str String to sanitize.
	 * @return string Sanitized string.
	 */
	function sanitize_text_field( $str ) {
		return trim( strip_tags( $str ) );
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	/**
	 * Mock add_filter function
	 *
	 * @param string   $hook_name    The name of the filter.
	 * @param callable $callback     The callback function.
	 * @param int      $priority     Optional. Priority. Default 10.
	 * @param int      $accepted_args Optional. Number of arguments. Default 1.
	 * @return bool Always returns true.
	 */
	function add_filter( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
		return true;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	/**
	 * Mock add_action function
	 *
	 * @param string   $hook_name    The name of the action.
	 * @param callable $callback     The callback function.
	 * @param int      $priority     Optional. Priority. Default 10.
	 * @param int      $accepted_args Optional. Number of arguments. Default 1.
	 * @return bool Always returns true.
	 */
	function add_action( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
		return true;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * Mock apply_filters function
	 *
	 * @param string $hook_name The name of the filter.
	 * @param mixed  $value     The value to filter.
	 * @param mixed  ...$args   Additional arguments.
	 * @return mixed The filtered value.
	 */
	function apply_filters( $hook_name, $value, ...$args ) {
		return $value;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	/**
	 * Mock do_action function
	 *
	 * @param string $hook_name The name of the action.
	 * @param mixed  ...$args   Additional arguments.
	 * @return void
	 */
	function do_action( $hook_name, ...$args ) {
		// Do nothing.
	}
}

// Load only the helpers.php file for basic function testing.
require_once dirname( __DIR__ ) . '/includes/helpers.php';

echo "WP REST Auth OAuth2 Unit Test environment loaded successfully!\n";
echo 'PHP version: ' . PHP_VERSION . "\n\n";
