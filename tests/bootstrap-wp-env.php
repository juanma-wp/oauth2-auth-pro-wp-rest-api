<?php
/**
 * PHPUnit bootstrap file for WP REST Auth OAuth2 using wp-env.
 *
 * @package WP_REST_Auth_OAuth2
 */

// Determine the tests directory
$_tests_dir = getenv( 'WP_TESTS_DIR' );
if ( ! $_tests_dir ) {
    $_tests_dir = '/tmp/wordpress-tests-lib';
}

// Set up the WordPress testing environment
if ( ! file_exists( $_tests_dir . '/includes/functions.php' ) ) {
    echo "Could not find $_tests_dir/includes/functions.php\n";
    echo "Please check that the WordPress test suite is installed.\n";
    echo "For wp-env, this should be automatically set up.\n";
    exit( 1 );
}

// Give access to tests_add_filter() function.
require_once $_tests_dir . '/includes/functions.php';

/**
 * Manually load the plugin being tested.
 */
function _manually_load_oauth2_plugin() {
    // Load the plugin
    require dirname( __DIR__ ) . '/wp-rest-auth-oauth2.php';
}
tests_add_filter( 'muplugins_loaded', '_manually_load_oauth2_plugin' );

// Start up the WP testing environment.
require $_tests_dir . '/includes/bootstrap.php';