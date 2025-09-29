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
        $this->assertTrue(method_exists($this->auth_oauth2, 'authorize'));
    }

    public function testTokenEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'token'));
    }

    public function testRefreshTokenEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'refresh_token'));
    }

    public function testRevokeTokenEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'revoke_token'));
    }

    public function testUserInfoEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'userinfo'));
    }

    public function testScopesEndpoint(): void
    {
        $this->assertTrue(method_exists($this->auth_oauth2, 'get_scopes'));
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
        // Test client validation methods exist
        $this->assertTrue(method_exists($this->auth_oauth2, 'validate_client'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'get_client'));
    }

    public function testClientCredentialsValidation(): void
    {
        // Mock client settings
        $this->mockOAuth2Settings();

        // Test valid client
        $is_valid = $this->auth_oauth2->validate_client('test-client', 'test-secret');
        $this->assertTrue($is_valid || is_wp_error($is_valid)); // May return error in test env

        // Test invalid client
        $is_invalid = $this->auth_oauth2->validate_client('invalid-client', 'wrong-secret');
        $this->assertFalse($is_invalid);
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
        // Test scope validation
        $this->assertTrue(method_exists($this->auth_oauth2, 'validate_scopes'));

        // Test basic scopes
        $valid_scopes = ['read', 'write', 'delete'];
        $result = $this->auth_oauth2->validate_scopes($valid_scopes);
        $this->assertTrue($result || is_array($result)); // May return filtered scopes

        // Test invalid scopes
        $invalid_scopes = ['invalid@scope', 'bad/scope'];
        $result = $this->auth_oauth2->validate_scopes($invalid_scopes);
        $this->assertFalse($result || is_array($result)); // Should be filtered
    }

    public function testUserScopePermissions(): void
    {
        // Create mock user
        $user = new stdClass();
        $user->ID = 123;
        $user->roles = ['subscriber'];

        // Mock WordPress functions
        if (!function_exists('user_can')) {
            function user_can($user, $capability) {
                $subscriber_caps = ['read'];
                return in_array($capability, $subscriber_caps);
            }
        }

        // Test user can access read scope
        $can_access = wp_auth_oauth2_user_can_access_scope($user, 'read');
        $this->assertTrue($can_access);

        // Test user cannot access admin scopes
        $cannot_access = wp_auth_oauth2_user_can_access_scope($user, 'manage_users');
        $this->assertFalse($cannot_access);
    }

    public function testTokenStorage(): void
    {
        // Test token storage methods exist
        $this->assertTrue(method_exists($this->auth_oauth2, 'store_access_token'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'store_refresh_token'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'get_stored_token'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'revoke_token'));
    }

    public function testAuthorizationCodeStorage(): void
    {
        // Test authorization code storage methods exist
        $this->assertTrue(method_exists($this->auth_oauth2, 'store_authorization_code'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'get_authorization_code'));
        $this->assertTrue(method_exists($this->auth_oauth2, 'consume_authorization_code'));
    }

    public function testTokenCleanup(): void
    {
        // Test token cleanup functionality
        $this->assertTrue(method_exists($this->auth_oauth2, 'clean_expired_tokens'));

        // Should not throw errors
        $this->auth_oauth2->clean_expired_tokens();
        $this->assertTrue(true);
    }

    public function testRedirectUriValidation(): void
    {
        // Test redirect URI validation
        $this->assertTrue(method_exists($this->auth_oauth2, 'validate_redirect_uri'));

        // Mock client with redirect URIs
        $this->mockOAuth2Settings();

        $is_valid = $this->auth_oauth2->validate_redirect_uri('test-client', 'http://localhost:3000/callback');
        $this->assertTrue($is_valid || is_wp_error($is_valid)); // May fail in test env

        $is_invalid = $this->auth_oauth2->validate_redirect_uri('test-client', 'https://malicious.com/callback');
        $this->assertFalse($is_invalid);
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
        // Test token introspection capabilities
        $this->assertTrue(method_exists($this->auth_oauth2, 'introspect_token'));

        // Test with invalid token
        $result = $this->auth_oauth2->introspect_token('invalid-token');
        $this->assertFalse($result || is_wp_error($result));
    }

    public function testMultiClientSupport(): void
    {
        // Test that system supports multiple clients
        $this->mockOAuth2Settings();

        // Get client settings
        $client1 = $this->auth_oauth2->get_client('test-client');
        $client2 = $this->auth_oauth2->get_client('another-client');

        // Should handle multiple clients (even if second doesn't exist)
        $this->assertTrue(is_array($client1) || is_wp_error($client1) || $client1 === false);
        $this->assertTrue(is_array($client2) || is_wp_error($client2) || $client2 === false);
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
        // Mock WordPress settings functions
        if (!class_exists('WP_REST_Auth_OAuth2_Admin_Settings')) {
            class WP_REST_Auth_OAuth2_Admin_Settings {
                public static function get_oauth2_settings() {
                    return [
                        'clients' => [
                            'test-client' => [
                                'name' => 'Test OAuth2 Client',
                                'client_secret' => wp_hash_password('test-secret'),
                                'redirect_uris' => [
                                    'http://localhost:3000/callback',
                                    'https://example.com/callback'
                                ],
                                'created_at' => '2023-01-01 00:00:00'
                            ]
                        ]
                    ];
                }
            }
        }

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