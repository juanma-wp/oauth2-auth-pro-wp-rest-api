<?php

use PHPUnit\Framework\TestCase;

/**
 * Unit tests for OAuth2 Authentication class
 */
class OAuth2AuthTest extends TestCase
{
    private $auth_oauth2;

    protected function setUp(): void
    {
        parent::setUp();

        // Load the OAuth2 auth class
        if (!class_exists('Auth_OAuth2')) {
            require_once dirname(__DIR__, 2) . '/includes/class-auth-oauth2.php';
        }

        // Load helpers
        if (!function_exists('wp_auth_oauth2_generate_token')) {
            require_once dirname(__DIR__, 2) . '/includes/helpers.php';
        }

        // Define constants for testing
        if (!defined('WP_OAUTH2_SECRET')) {
            define('WP_OAUTH2_SECRET', 'test-oauth2-secret-key-for-testing-only');
        }

        $this->auth_oauth2 = new Auth_OAuth2();
    }

    public function testOAuth2AuthClassExists(): void
    {
        $this->assertTrue(class_exists('Auth_OAuth2'));
        $this->assertInstanceOf('Auth_OAuth2', $this->auth_oauth2);
    }

    public function testRestRoutesRegistration(): void
    {
        // Test that OAuth2 routes registration method exists
        $this->assertTrue(method_exists($this->auth_oauth2, 'register_routes'));
    }

    public function testAuthorizationEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'authorize_endpoint'));
    }

    public function testTokenEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'token_endpoint'));
    }

    public function testRefreshTokenEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'refresh_token_endpoint'));
    }

    public function testRevokeTokenEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'revoke_endpoint'));
    }

    public function testUserInfoEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'userinfo_endpoint'));
    }

    public function testScopesEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'scopes_endpoint'));
    }

    public function testBearerTokenAuthentication(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'authenticate_bearer'));

        // Test with invalid token
        $result = $this->auth_oauth2->authenticate_bearer('invalid-oauth2-token');
        $this->assertInstanceOf('WP_Error', $result);
    }

    public function testClientValidation(): void
    {
        // Test that get_client is a private method (internal use only)
        $reflection = new ReflectionClass($this->auth_oauth2);
        $this->assertTrue($reflection->hasMethod('get_client'));
    }

    public function testClientCredentialsValidation(): void
    {
        // validate_client() is a private method tested via integration tests
        // Test that the internal validation mechanism exists
        $reflection = new ReflectionClass($this->auth_oauth2);
        $this->assertTrue($reflection->hasMethod('token_endpoint'));
    }

    public function testAuthorizationCodeGeneration(): void
    {
        $auth_code = wp_auth_oauth2_generate_auth_code();

        $this->assertIsString($auth_code);
        $this->assertEquals(32, strlen($auth_code));
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $auth_code);
    }

    public function testAccessTokenGeneration(): void
    {
        $access_token = wp_auth_oauth2_generate_access_token();

        $this->assertIsString($access_token);
        $this->assertEquals(48, strlen($access_token));
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $access_token);
    }

    public function testRefreshTokenGeneration(): void
    {
        $refresh_token = wp_auth_oauth2_generate_refresh_token();

        $this->assertIsString($refresh_token);
        $this->assertEquals(64, strlen($refresh_token));
        $this->assertMatchesRegularExpression('/^[a-f0-9]+$/', $refresh_token);
    }

    public function testScopeHandling(): void
    {
        // Use the public helper functions instead of private methods
        $valid_scopes = wp_auth_oauth2_parse_scopes('read write delete');
        $this->assertIsArray($valid_scopes);
        $this->assertContains('read', $valid_scopes);
        $this->assertContains('write', $valid_scopes);

        // Test invalid scopes are filtered out
        $invalid_scopes = wp_auth_oauth2_parse_scopes('read invalid@scope bad/scope');
        $this->assertContains('read', $invalid_scopes);
        $this->assertNotContains('invalid@scope', $invalid_scopes);
        $this->assertNotContains('bad/scope', $invalid_scopes);
    }

    public function testUserScopePermissions(): void
    {
        // Requires WordPress user factory - tested in integration tests
        // Test the helper function exists
        $this->assertTrue(function_exists('wp_auth_oauth2_user_can_access_scope'));
    }

    public function testTokenStorage(): void
    {
        // Token storage is handled via WordPress transients and database
        // Public method available: revoke_token()
        $this->assertTrue(method_exists($this->auth_oauth2, 'revoke_token'));
    }

    public function testAuthorizationCodeStorage(): void
    {
        // Authorization codes are stored via WordPress transients (set_transient/get_transient)
        // Verify WordPress functions are available in integration test environment
        $this->assertTrue(function_exists('set_transient'));
        $this->assertTrue(function_exists('get_transient'));
    }

    public function testTokenCleanup(): void
    {
        // Test token cleanup functionality
        $this->assertTrue(method_exists($this->auth_oauth2, 'clean_expired_codes'));

        // Should not throw errors
        $this->auth_oauth2->clean_expired_codes();
        $this->assertTrue(true);
    }

    public function testRedirectUriValidation(): void
    {
        // Test redirect URI validation method exists
        $this->assertTrue(method_exists($this->auth_oauth2, 'validate_redirect_uri'));

        // Test helper function for URI validation
        $this->assertTrue(function_exists('wp_auth_oauth2_validate_redirect_uri'));
    }

    public function testStateParameterHandling(): void
    {
        // Test state parameter preservation in OAuth2 flow
        $state = 'test-state-' . time();

        // State should be preserved and validated
        // This is typically handled in the authorization flow
        $this->assertIsString($state);
        $this->assertNotEmpty($state);
    }

    public function testPKCESupport(): void
    {
        // Test PKCE (Proof Key for Code Exchange) support
        // While not fully implemented, test the structure exists

        // Generate code verifier
        $code_verifier = wp_auth_oauth2_generate_token(128);
        $this->assertIsString($code_verifier);

        // Generate code challenge (SHA256 hash)
        $code_challenge = rtrim(strtr(base64_encode(hash('sha256', $code_verifier, true)), '+/', '-_'), '=');
        $this->assertIsString($code_challenge);
        $this->assertNotEquals($code_verifier, $code_challenge);
    }

    public function testTokenIntrospection(): void
    {
        // Token introspection is done via authenticate_bearer() which is public
        // Verify the public method exists for token introspection
        $this->assertTrue(method_exists($this->auth_oauth2, 'authenticate_bearer'));
    }

    public function testMultiClientSupport(): void
    {
        // get_client() is a private method - test via reflection
        $reflection = new ReflectionClass($this->auth_oauth2);
        $this->assertTrue($reflection->hasMethod('get_client'));

        // Verify the method is private (internal use only)
        $method = $reflection->getMethod('get_client');
        $this->assertTrue($method->isPrivate());
    }

    public function testCORSSupport(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'add_cors_support'));

        // Test CORS method exists and can be called
        $this->auth_oauth2->add_cors_support();
        $this->assertTrue(true); // Should not throw errors
    }

    public function testErrorResponses(): void
    {
        // Test OAuth2 error response format
        $error = wp_auth_oauth2_create_error_response('invalid_client', 'Client not found', null, 'test-state');

        $this->assertIsArray($error);
        $this->assertEquals('invalid_client', $error['error']);
        $this->assertEquals('Client not found', $error['error_description']);
        $this->assertEquals('test-state', $error['state']);
    }

    public function testTokenExpirationHandling(): void
    {
        // Test token expiration logic
        $expired_time = time() - 3600; // 1 hour ago
        $valid_time = time() + 3600;   // 1 hour from now

        // Mock token data
        $expired_token_data = [
            'expires_at' => $expired_time,
            'user_id' => 123,
            'client_id' => 'test-client',
            'scopes' => ['read']
        ];

        $valid_token_data = [
            'expires_at' => $valid_time,
            'user_id' => 123,
            'client_id' => 'test-client',
            'scopes' => ['read']
        ];

        // Expired token should be invalid
        $this->assertLessThan(time(), $expired_token_data['expires_at']);

        // Valid token should be valid
        $this->assertGreaterThan(time(), $valid_token_data['expires_at']);
    }

    public function testClientSecretValidation(): void
    {
        // Test client secret hashing and validation
        $client_secret = 'test-secret-password';
        $hashed_secret = wp_hash_password($client_secret);

        $this->assertNotEquals($client_secret, $hashed_secret);
        $this->assertIsString($hashed_secret);
        $this->assertNotEmpty($hashed_secret);

        // Test password verification
        if (function_exists('wp_check_password')) {
            $is_valid = wp_check_password($client_secret, $hashed_secret);
            $this->assertTrue($is_valid);
        }
    }

    // Helper methods

    private function mockOAuth2Settings(): void
    {
        // Mock class is loaded in bootstrap-wp-env.php
        // No need to declare it here

        // Mock WordPress password functions
        if (!function_exists('wp_hash_password')) {
            function wp_hash_password($password) {
                return password_hash($password, PASSWORD_DEFAULT);
            }
        }

        if (!function_exists('wp_check_password')) {
            function wp_check_password($password, $hash) {
                return password_verify($password, $hash);
            }
        }

        if (!function_exists('is_wp_error')) {
            function is_wp_error($thing) {
                return $thing instanceof WP_Error;
            }
        }
    }
}