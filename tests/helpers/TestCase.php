<?php

namespace WPRestAuthOAuth2\Tests\Helpers;

use PHPUnit\Framework\TestCase as BaseTestCase;

/**
 * Base test case for WP REST Auth OAuth2 plugin tests
 */
class TestCase extends BaseTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Reset global state before each test
        $this->resetGlobalState();

        // Set up test constants if not already defined
        $this->setupTestConstants();
    }

    protected function tearDown(): void
    {
        // Clean up after each test
        $this->cleanupTestData();

        parent::tearDown();
    }

    /**
     * Reset global state between tests
     */
    protected function resetGlobalState(): void
    {
        // Reset $_SERVER variables
        $_SERVER['HTTP_AUTHORIZATION'] = null;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';

        // Reset WordPress globals if they exist
        if (isset($GLOBALS['wp_rest_server'])) {
            unset($GLOBALS['wp_rest_server']);
        }
    }

    /**
     * Setup test constants
     */
    protected function setupTestConstants(): void
    {
        if (!defined('WP_OAUTH2_SECRET')) {
            define('WP_OAUTH2_SECRET', 'test-oauth2-secret-key-for-testing-purposes-only-never-use-in-production');
        }

        if (!defined('ABSPATH')) {
            define('ABSPATH', '/tmp/wordpress/');
        }
    }

    /**
     * Clean up test data
     */
    protected function cleanupTestData(): void
    {
        // Remove any test transients or options
        // This would normally use WordPress functions, but for unit tests we'll mock it
    }

    /**
     * Create a mock WordPress user
     */
    protected function createMockUser($user_id = 1, $user_login = 'testuser', $user_email = 'test@example.com'): \stdClass
    {
        $user = new \stdClass();
        $user->ID = $user_id;
        $user->user_login = $user_login;
        $user->user_email = $user_email;
        $user->display_name = 'Test User';
        $user->roles = ['subscriber'];

        return $user;
    }

    /**
     * Create a test OAuth2 client
     */
    protected function createTestOAuth2Client($client_id = 'test-client'): array
    {
        return [
            'client_id' => $client_id,
            'name' => 'Test OAuth2 Client',
            'client_secret' => wp_hash_password('test-secret'),
            'redirect_uris' => [
                'http://localhost:3000/callback',
                'https://example.com/callback'
            ],
            'created_at' => current_time('mysql')
        ];
    }

    /**
     * Create a test OAuth2 access token
     */
    protected function createTestOAuth2Token($user_id = 1, $scopes = ['read'], $client_id = 'test-client'): string
    {
        return 'oauth2_' . hash('sha256', $user_id . $client_id . implode(',', $scopes) . time());
    }

    /**
     * Create a test OAuth2 authorization code
     */
    protected function createTestAuthCode($user_id = 1, $client_id = 'test-client'): string
    {
        return 'auth_code_' . hash('sha256', $user_id . $client_id . time());
    }

    /**
     * Create a test OAuth2 refresh token
     */
    protected function createTestRefreshToken(): string
    {
        return wp_auth_oauth2_generate_refresh_token();
    }

    /**
     * Mock WordPress option functions
     */
    protected function mockWordPressOptions(): void
    {
        if (!function_exists('get_option')) {
            function get_option($option, $default = false) {
                static $options = [
                    'wp_rest_auth_oauth2_settings' => [
                        'clients' => [
                            'test-client' => [
                                'name' => 'Test Client',
                                'client_secret' => wp_hash_password('test-secret'),
                                'redirect_uris' => ['http://localhost:3000/callback'],
                                'created_at' => '2023-01-01 00:00:00'
                            ]
                        ]
                    ]
                ];
                return $options[$option] ?? $default;
            }
        }

        if (!function_exists('update_option')) {
            function update_option($option, $value) {
                static $options = [];
                $options[$option] = $value;
                return true;
            }
        }
    }

    /**
     * Assert that an OAuth2 response contains required fields
     */
    protected function assertValidOAuth2Response($response): void
    {
        $this->assertArrayHasKey('access_token', $response);
        $this->assertArrayHasKey('token_type', $response);
        $this->assertArrayHasKey('expires_in', $response);
        $this->assertEquals('Bearer', $response['token_type']);
    }

    /**
     * Assert that an OAuth2 error response is valid
     */
    protected function assertValidOAuth2Error($response): void
    {
        $this->assertArrayHasKey('error', $response);
        $this->assertArrayHasKey('error_description', $response);
    }

    /**
     * Assert that OAuth2 scopes are valid
     */
    protected function assertValidOAuth2Scopes($scopes): void
    {
        $this->assertIsArray($scopes);

        foreach ($scopes as $scope) {
            $this->assertIsString($scope);
            $this->assertTrue(wp_auth_oauth2_validate_scope($scope));
        }
    }

    /**
     * Create a mock HTTP request
     */
    protected function createMockRequest($method = 'GET', $url = '/', $headers = [], $body = null): array
    {
        return [
            'method' => $method,
            'url' => $url,
            'headers' => $headers,
            'body' => $body
        ];
    }

    /**
     * Simulate an authenticated request
     */
    protected function setAuthorizationHeader($token, $type = 'Bearer'): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = $type . ' ' . $token;
    }

    /**
     * Create mock OAuth2 authorization request
     */
    protected function createMockAuthRequest($client_id = 'test-client', $scopes = ['read']): array
    {
        return [
            'client_id' => $client_id,
            'redirect_uri' => 'http://localhost:3000/callback',
            'response_type' => 'code',
            'scope' => implode(' ', $scopes),
            'state' => 'test-state-' . time()
        ];
    }

    /**
     * Create mock token request
     */
    protected function createMockTokenRequest($auth_code = 'test-auth-code', $client_id = 'test-client'): array
    {
        return [
            'grant_type' => 'authorization_code',
            'client_id' => $client_id,
            'client_secret' => 'test-secret',
            'code' => $auth_code,
            'redirect_uri' => 'http://localhost:3000/callback'
        ];
    }

    /**
     * Create mock proxy session
     */
    protected function createMockProxySession($user_id = 1): array
    {
        return [
            'user_id' => $user_id,
            'access_token' => $this->createTestOAuth2Token($user_id),
            'refresh_token' => $this->createTestRefreshToken(),
            'expires_at' => time() + 3600,
            'created_at' => time()
        ];
    }
}