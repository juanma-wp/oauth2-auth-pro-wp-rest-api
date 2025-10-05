<?php

use PHPUnit\Framework\TestCase;

/**
 * Basic Unit tests for OAuth2 Helper functions that don't require WordPress
 */
class BasicHelpersTest extends TestCase
{
	protected function setUp(): void
	{
		parent::setUp();

		// Load helpers
		if ( ! function_exists( 'wp_auth_oauth2_generate_token' ) ) {
			require_once dirname( __DIR__, 2 ) . '/includes/helpers.php';
		}

		// Define constants for testing
		if ( ! defined( 'WP_OAUTH2_SECRET' ) ) {
			define( 'WP_OAUTH2_SECRET', 'test-oauth2-secret-key-for-testing-only' );
		}
	}

	public function testTokenGenerationWithDefaultLength(): void
	{
		$token = wp_auth_oauth2_generate_token();

		$this->assertIsString( $token );
		$this->assertEquals( 64, strlen( $token ) );
	}

	public function testTokenHashing(): void
	{
		$token  = 'test-oauth2-token-123';
		$secret = 'test-secret';

		$hash = wp_auth_oauth2_hash_token( $token, $secret );

		$this->assertIsString( $hash );
		$this->assertEquals( 64, strlen( $hash ) ); // SHA256 produces 64 char hex string

		// Same input should produce same hash
		$hash2 = wp_auth_oauth2_hash_token( $token, $secret );
		$this->assertEquals( $hash, $hash2 );

		// Different secret should produce different hash
		$hash3 = wp_auth_oauth2_hash_token( $token, 'different-secret' );
		$this->assertNotEquals( $hash, $hash3 );
	}

	public function testOAuth2TokenGeneration(): void
	{
		$access_token  = wp_auth_oauth2_generate_access_token();
		$refresh_token = wp_auth_oauth2_generate_refresh_token();
		$auth_code     = wp_auth_oauth2_generate_auth_code();

		$this->assertIsString( $access_token );
		$this->assertEquals( 48, strlen( $access_token ) );

		$this->assertIsString( $refresh_token );
		$this->assertEquals( 64, strlen( $refresh_token ) );

		$this->assertIsString( $auth_code );
		$this->assertEquals( 32, strlen( $auth_code ) );

		// All should be different
		$this->assertNotEquals( $access_token, $refresh_token );
		$this->assertNotEquals( $access_token, $auth_code );
		$this->assertNotEquals( $refresh_token, $auth_code );
	}

	public function testScopeValidation(): void
	{
		// Valid scopes
		$this->assertTrue( wp_auth_oauth2_validate_scope( 'read' ) );
		$this->assertTrue( wp_auth_oauth2_validate_scope( 'write' ) );
		$this->assertTrue( wp_auth_oauth2_validate_scope( 'read:posts' ) );
		$this->assertTrue( wp_auth_oauth2_validate_scope( 'api.users' ) );
		$this->assertTrue( wp_auth_oauth2_validate_scope( 'manage_users' ) );

		// Invalid scopes
		$this->assertFalse( wp_auth_oauth2_validate_scope( 'read write' ) ); // spaces
		$this->assertFalse( wp_auth_oauth2_validate_scope( 'read@posts' ) ); // special chars
		$this->assertFalse( wp_auth_oauth2_validate_scope( 'read/posts' ) ); // slashes
		$this->assertFalse( wp_auth_oauth2_validate_scope( '' ) ); // empty
	}

	public function testScopeParsing(): void
	{
		$scope_string = 'read write delete manage_users';
		$scopes       = wp_auth_oauth2_parse_scopes( $scope_string );

		$this->assertIsArray( $scopes );
		$this->assertCount( 4, $scopes );
		$this->assertContains( 'read', $scopes );
		$this->assertContains( 'write', $scopes );
		$this->assertContains( 'delete', $scopes );
		$this->assertContains( 'manage_users', $scopes );

		// Test with invalid scopes (should be filtered out)
		$mixed_string    = 'read invalid@scope write bad/scope delete';
		$filtered_scopes = wp_auth_oauth2_parse_scopes( $mixed_string );

		$this->assertCount( 3, $filtered_scopes );
		$this->assertContains( 'read', $filtered_scopes );
		$this->assertContains( 'write', $filtered_scopes );
		$this->assertContains( 'delete', $filtered_scopes );
		$this->assertNotContains( 'invalid@scope', $filtered_scopes );
		$this->assertNotContains( 'bad/scope', $filtered_scopes );
	}

	public function testRedirectUriValidation(): void
	{
		// Valid URIs
		$this->assertTrue( wp_auth_oauth2_validate_redirect_uri( 'https://example.com/callback' ) );
		$this->assertTrue( wp_auth_oauth2_validate_redirect_uri( 'https://app.example.com/oauth/callback' ) );
		$this->assertTrue( wp_auth_oauth2_validate_redirect_uri( 'http://localhost:3000/callback' ) ); // localhost exception
		$this->assertTrue( wp_auth_oauth2_validate_redirect_uri( 'http://127.0.0.1:8080/callback' ) ); // localhost exception

		// Invalid URIs
		$this->assertFalse( wp_auth_oauth2_validate_redirect_uri( 'http://example.com/callback' ) ); // http for non-localhost
		$this->assertFalse( wp_auth_oauth2_validate_redirect_uri( 'ftp://example.com/callback' ) ); // wrong scheme
		$this->assertFalse( wp_auth_oauth2_validate_redirect_uri( 'invalid-url' ) ); // not a URL
		$this->assertFalse( wp_auth_oauth2_validate_redirect_uri( '' ) ); // empty
	}

	public function testOAuth2ErrorResponses(): void
	{
		$error_response = wp_auth_oauth2_create_error_response( 'invalid_request', null, null, 'test-state' );

		$this->assertIsArray( $error_response );
		$this->assertEquals( 'invalid_request', $error_response['error'] );
		$this->assertArrayHasKey( 'error_description', $error_response );
		$this->assertEquals( 'test-state', $error_response['state'] );

		// Test with custom description
		$custom_error = wp_auth_oauth2_create_error_response( 'access_denied', 'User denied access' );

		$this->assertEquals( 'access_denied', $custom_error['error'] );
		$this->assertEquals( 'User denied access', $custom_error['error_description'] );
	}

	public function testErrorDescriptions(): void
	{
		$description = wp_auth_oauth2_get_error_description( 'invalid_request' );
		$this->assertIsString( $description );
		$this->assertNotEmpty( $description );

		$description = wp_auth_oauth2_get_error_description( 'invalid_client' );
		$this->assertIsString( $description );
		$this->assertNotEmpty( $description );

		// Unknown error should return default
		$description = wp_auth_oauth2_get_error_description( 'unknown_error' );
		$this->assertEquals( 'Unknown error occurred.', $description );
	}

	public function testDebugLogging(): void
	{
		// Test debug log function exists
		$this->assertTrue( function_exists( 'wp_auth_oauth2_debug_log' ) );

		// Test function can be called without errors
		wp_auth_oauth2_debug_log( 'OAuth2 test message', array( 'data' => 'test' ) );
		$this->assertTrue( true ); // Should not throw errors
	}
}
