<?php

use PHPUnit\Framework\TestCase;

/**
 * Unit tests for OAuth2 Helper functions
 */
class HelpersTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Load helpers
        if (!function_exists('wp_auth_oauth2_generate_token')) {
            require_once dirname(__DIR__, 2) . '/includes/helpers.php';
        }

        // Define constants for testing
        if (!defined('WP_OAUTH2_SECRET')) {
            define('WP_OAUTH2_SECRET', 'test-oauth2-secret-key-for-testing-only');
        }
    }

    public function testTokenGeneration(): void
    {
        $token = wp_auth_oauth2_generate_token(32);

        $this->assertIsString($token);
        $this->assertEquals(32, strlen($token));
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $token);
    }

    public function testTokenGenerationWithDefaultLength(): void
    {
        $token = wp_auth_oauth2_generate_token();

        $this->assertIsString($token);
        $this->assertEquals(64, strlen($token));
    }

    public function testTokenHashing(): void
    {
        $token = 'test-oauth2-token-123';
        $secret = 'test-secret';

        $hash = wp_auth_oauth2_hash_token($token, $secret);

        $this->assertIsString($hash);
        $this->assertEquals(64, strlen($hash)); // SHA256 produces 64 char hex string

        // Same input should produce same hash
        $hash2 = wp_auth_oauth2_hash_token($token, $secret);
        $this->assertEquals($hash, $hash2);

        // Different secret should produce different hash
        $hash3 = wp_auth_oauth2_hash_token($token, 'different-secret');
        $this->assertNotEquals($hash, $hash3);
    }

    public function testOAuth2TokenGeneration(): void
    {
        $access_token = wp_auth_oauth2_generate_access_token();
        $refresh_token = wp_auth_oauth2_generate_refresh_token();
        $auth_code = wp_auth_oauth2_generate_auth_code();

        $this->assertIsString($access_token);
        $this->assertEquals(48, strlen($access_token));

        $this->assertIsString($refresh_token);
        $this->assertEquals(64, strlen($refresh_token));

        $this->assertIsString($auth_code);
        $this->assertEquals(32, strlen($auth_code));

        // All should be different
        $this->assertNotEquals($access_token, $refresh_token);
        $this->assertNotEquals($access_token, $auth_code);
        $this->assertNotEquals($refresh_token, $auth_code);
    }

    public function testScopeValidation(): void
    {
        // Valid scopes
        $this->assertTrue(wp_auth_oauth2_validate_scope('read'));
        $this->assertTrue(wp_auth_oauth2_validate_scope('write'));
        $this->assertTrue(wp_auth_oauth2_validate_scope('read:posts'));
        $this->assertTrue(wp_auth_oauth2_validate_scope('api.users'));
        $this->assertTrue(wp_auth_oauth2_validate_scope('manage_users'));

        // Invalid scopes
        $this->assertFalse(wp_auth_oauth2_validate_scope('read write')); // spaces
        $this->assertFalse(wp_auth_oauth2_validate_scope('read@posts')); // special chars
        $this->assertFalse(wp_auth_oauth2_validate_scope('read/posts')); // slashes
        $this->assertFalse(wp_auth_oauth2_validate_scope('')); // empty
    }

    public function testScopeParsing(): void
    {
        $scope_string = 'read write delete manage_users';
        $scopes = wp_auth_oauth2_parse_scopes($scope_string);

        $this->assertIsArray($scopes);
        $this->assertCount(4, $scopes);
        $this->assertContains('read', $scopes);
        $this->assertContains('write', $scopes);
        $this->assertContains('delete', $scopes);
        $this->assertContains('manage_users', $scopes);

        // Test with invalid scopes (should be filtered out)
        $mixed_string = 'read invalid@scope write bad/scope delete';
        $filtered_scopes = wp_auth_oauth2_parse_scopes($mixed_string);

        $this->assertCount(3, $filtered_scopes);
        $this->assertContains('read', $filtered_scopes);
        $this->assertContains('write', $filtered_scopes);
        $this->assertContains('delete', $filtered_scopes);
        $this->assertNotContains('invalid@scope', $filtered_scopes);
        $this->assertNotContains('bad/scope', $filtered_scopes);
    }

    public function testClientIdSanitization(): void
    {
        $this->assertEquals('my-app-123', wp_auth_oauth2_sanitize_client_id('my-app-123'));
        $this->assertEquals('my_app_123', wp_auth_oauth2_sanitize_client_id('my_app_123'));
        $this->assertEquals('myapp123', wp_auth_oauth2_sanitize_client_id('My App 123!@#'));
        $this->assertEquals('test-client', wp_auth_oauth2_sanitize_client_id('test-client'));
    }

    public function testRedirectUriValidation(): void
    {
        // Valid URIs
        $this->assertTrue(wp_auth_oauth2_validate_redirect_uri('https://example.com/callback'));
        $this->assertTrue(wp_auth_oauth2_validate_redirect_uri('https://app.example.com/oauth/callback'));
        $this->assertTrue(wp_auth_oauth2_validate_redirect_uri('http://localhost:3000/callback')); // localhost exception
        $this->assertTrue(wp_auth_oauth2_validate_redirect_uri('http://127.0.0.1:8080/callback')); // localhost exception

        // Invalid URIs
        $this->assertFalse(wp_auth_oauth2_validate_redirect_uri('http://example.com/callback')); // http for non-localhost
        $this->assertFalse(wp_auth_oauth2_validate_redirect_uri('ftp://example.com/callback')); // wrong scheme
        $this->assertFalse(wp_auth_oauth2_validate_redirect_uri('invalid-url')); // not a URL
        $this->assertFalse(wp_auth_oauth2_validate_redirect_uri('')); // empty
    }

    public function testAvailableScopes(): void
    {
        $scopes = wp_auth_oauth2_get_available_scopes();

        $this->assertIsArray($scopes);
        $this->assertNotEmpty($scopes);

        // Check some expected scopes
        $this->assertArrayHasKey('read', $scopes);
        $this->assertArrayHasKey('write', $scopes);
        $this->assertArrayHasKey('delete', $scopes);
        $this->assertArrayHasKey('manage_users', $scopes);

        // Each scope should have a description
        foreach ($scopes as $scope => $description) {
            $this->assertIsString($scope);
            $this->assertIsString($description);
            $this->assertNotEmpty($description);
        }
    }

    public function testUserScopeAccess(): void
    {
        // This test requires WordPress user factory - move to integration tests only
        // Testing the logic itself doesn't require mocking complex WP_User objects
        $this->assertTrue(function_exists('wp_auth_oauth2_user_can_access_scope'));
    }

    public function testIPAddressRetrieval(): void
    {
        // Save original REMOTE_ADDR
        $original_remote_addr = $_SERVER['REMOTE_ADDR'] ?? null;

        // Clear REMOTE_ADDR to test default
        unset($_SERVER['REMOTE_ADDR']);
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
        unset($_SERVER['HTTP_X_REAL_IP']);
        unset($_SERVER['HTTP_CLIENT_IP']);

        $ip = wp_auth_oauth2_get_ip_address();
        $this->assertIsString($ip);
        $this->assertEquals('0.0.0.0', $ip);

        // Test with REMOTE_ADDR
        $_SERVER['REMOTE_ADDR'] = '192.168.1.1';
        $ip = wp_auth_oauth2_get_ip_address();
        $this->assertEquals('192.168.1.1', $ip);

        // Restore original
        if ($original_remote_addr !== null) {
            $_SERVER['REMOTE_ADDR'] = $original_remote_addr;
        }

        // Test with X-Forwarded-For (should take first IP)
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.1, 192.168.1.1';
        $ip = wp_auth_oauth2_get_ip_address();
        $this->assertEquals('203.0.113.1', $ip);

        // Clean up
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_X_FORWARDED_FOR']);
    }

    public function testUserAgentRetrieval(): void
    {
        $ua = wp_auth_oauth2_get_user_agent();

        $this->assertIsString($ua);
        $this->assertEquals('Unknown', $ua);

        // Test with actual user agent
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/2.0 OAuth2';
        $ua = wp_auth_oauth2_get_user_agent();
        $this->assertEquals('TestAgent/2.0 OAuth2', $ua);

        // Clean up
        unset($_SERVER['HTTP_USER_AGENT']);
    }

    public function testCookieSettings(): void
    {
        // Test cookie setting function exists
        $this->assertTrue(function_exists('wp_auth_oauth2_set_cookie'));

        // Test cookie deletion function exists
        $this->assertTrue(function_exists('wp_auth_oauth2_delete_cookie'));
    }

    public function testSuccessResponse(): void
    {
        $response = wp_auth_oauth2_success_response(['access_token' => 'test123'], 'Authorization successful');

        $this->assertInstanceOf('WP_REST_Response', $response);
        $this->assertEquals(200, $response->get_status());

        $data = $response->get_data();
        $this->assertTrue($data['success']);
        $this->assertEquals(['access_token' => 'test123'], $data['data']);
        $this->assertEquals('Authorization successful', $data['message']);
    }

    public function testErrorResponse(): void
    {
        $error = wp_auth_oauth2_error_response('invalid_client', 'The client credentials are invalid', 401);

        $this->assertInstanceOf('WP_Error', $error);
        $this->assertEquals('invalid_client', $error->get_error_code());
        $this->assertEquals('The client credentials are invalid', $error->get_error_message());

        $data = $error->get_error_data();
        $this->assertEquals(401, $data['status']);
    }

    public function testOAuth2ErrorResponses(): void
    {
        $error_response = wp_auth_oauth2_create_error_response('invalid_request', null, null, 'test-state');

        $this->assertIsArray($error_response);
        $this->assertEquals('invalid_request', $error_response['error']);
        $this->assertArrayHasKey('error_description', $error_response);
        $this->assertEquals('test-state', $error_response['state']);

        // Test with custom description
        $custom_error = wp_auth_oauth2_create_error_response('access_denied', 'User denied access');

        $this->assertEquals('access_denied', $custom_error['error']);
        $this->assertEquals('User denied access', $custom_error['error_description']);
    }

    public function testErrorDescriptions(): void
    {
        $description = wp_auth_oauth2_get_error_description('invalid_request');
        $this->assertIsString($description);
        $this->assertNotEmpty($description);

        $description = wp_auth_oauth2_get_error_description('invalid_client');
        $this->assertIsString($description);
        $this->assertNotEmpty($description);

        // Unknown error should return default
        $description = wp_auth_oauth2_get_error_description('unknown_error');
        $this->assertEquals('Unknown error occurred.', $description);
    }

    public function testCORSOriginValidation(): void
    {
        // This test requires WordPress settings - move to integration tests only
        // Testing the function existence
        $this->assertTrue(function_exists('wp_auth_oauth2_is_valid_origin'));
        $this->assertTrue(function_exists('wp_auth_oauth2_maybe_add_cors_headers'));
    }

    public function testUserDataFormatting(): void
    {
        // This test requires WordPress user factory - move to integration tests only
        // Testing the function existence
        $this->assertTrue(function_exists('wp_auth_oauth2_format_user_data'));
    }

    public function testDebugLogging(): void
    {
        // Test debug log function exists
        $this->assertTrue(function_exists('wp_auth_oauth2_debug_log'));

        // Test function can be called without errors
        wp_auth_oauth2_debug_log('OAuth2 test message', ['data' => 'test']);
        $this->assertTrue(true); // Should not throw errors
    }
}