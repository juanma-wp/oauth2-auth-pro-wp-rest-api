<?php
/**
 * PHPUnit bootstrap file for WP REST Auth OAuth2.
 *
 * @package WP_REST_Auth_OAuth2
 */

$_tests_dir = getenv( 'WP_TESTS_DIR' );

if ( ! $_tests_dir ) {
    $_tests_dir = rtrim( sys_get_temp_dir(), '/\\' ) . '/wordpress-tests-lib';
}

// Forward custom PHPUnit Polyfills configuration to PHPUnit bootstrap file.
$_phpunit_polyfills_path = getenv( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH' );
if ( false !== $_phpunit_polyfills_path ) {
    define( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH', $_phpunit_polyfills_path );
}

if ( ! file_exists( "{$_tests_dir}/includes/functions.php" ) ) {
    echo "Could not find {$_tests_dir}/includes/functions.php, have you run bin/install-wp-tests.sh ?" . PHP_EOL;
    exit( 1 );
}

// Give access to tests_add_filter() function.
require_once "{$_tests_dir}/includes/functions.php";

/**
 * Manually load the plugin being tested.
 */
function _manually_load_oauth2_plugin() {
    // Define test constants before loading the plugin
    if (!defined('WP_OAUTH2_SECRET')) {
        define('WP_OAUTH2_SECRET', 'test-oauth2-secret-key-for-testing-only-never-use-in-production');
    }

    require dirname( dirname( __FILE__ ) ) . '/oauth2-auth-pro-wp-rest-api.php';
}

tests_add_filter( 'muplugins_loaded', '_manually_load_oauth2_plugin' );

// Start up the WP testing environment.
require "{$_tests_dir}/includes/bootstrap.php";