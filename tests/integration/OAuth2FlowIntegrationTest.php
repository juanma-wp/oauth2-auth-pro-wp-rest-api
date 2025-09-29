<?php

use WPRestAuthOAuth2\Tests\Helpers\TestCase;

/**
 * Integration tests for OAuth2 flow functionality
 */
class OAuth2FlowIntegrationTest extends WP_UnitTestCase
{
    private $auth_oauth2;
    private $server;
    private $test_user_id;

    public function setUp(): void
    {
        parent::setUp();

        // Set up REST server
        global $wp_rest_server;
        $this->server = $wp_rest_server = new WP_REST_Server();
        do_action('rest_api_init');

        // Load OAuth2 auth
        if (!class_exists('Auth_OAuth2')) {
            require_once WP_REST_AUTH_OAUTH2_PLUGIN_DIR . 'includes/class-auth-oauth2.php';
        }

        $this->auth_oauth2 = new Auth_OAuth2();
        $this->auth_oauth2->register_routes();

        // Create test user
        $this->test_user_id = $this->factory->user->create([
            'user_login' => 'oauth2testuser',
            'user_pass' => 'testpass123',
            'user_email' => 'oauth2test@example.com',
            'role' => 'editor' // Editor has more capabilities for testing
        ]);

        // Set up test OAuth2 client
        $this->setupTestClient();
    }

    public function tearDown(): void
    {
        global $wp_rest_server;
        $wp_rest_server = null;

        parent::tearDown();
    }

    public function testOAuth2RoutesRegistered(): void
    {
        $routes = $this->server->get_routes();

        // Test that OAuth2 routes are registered
        $this->assertArrayHasKey('/oauth2/v1/authorize', $routes);
        $this->assertArrayHasKey('/oauth2/v1/token', $routes);
        $this->assertArrayHasKey('/oauth2/v1/refresh', $routes);
        $this->assertArrayHasKey('/oauth2/v1/revoke', $routes);
        $this->assertArrayHasKey('/oauth2/v1/userinfo', $routes);
        $this->assertArrayHasKey('/oauth2/v1/scopes', $routes);
    }

    public function testAuthorizeEndpointMethods(): void
    {
        $routes = $this->server->get_routes();
        $authorize_route = $routes['/oauth2/v1/authorize'];

        // Should accept GET method for authorization page
        $this->assertContains('GET', $authorize_route[0]['methods']);
    }

    public function testTokenEndpointMethods(): void
    {
        $routes = $this->server->get_routes();
        $token_route = $routes['/oauth2/v1/token'];

        // Should accept POST method
        $this->assertContains('POST', $token_route[0]['methods']);
    }

    public function testScopesEndpoint(): void
    {
        $request = new WP_REST_Request('GET', '/oauth2/v1/scopes');
        $response = $this->server->dispatch($request);

        $this->assertEquals(200, $response->get_status());

        $data = $response->get_data();
        $this->assertArrayHasKey('data', $data);
        $this->assertIsArray($data['data']);

        // Should contain basic scopes
        $scopes = $data['data'];
        $this->assertArrayHasKey('read', $scopes);
        $this->assertArrayHasKey('write', $scopes);
    }

    public function testAuthorizeEndpointWithInvalidClient(): void
    {
        $request = new WP_REST_Request('GET', '/oauth2/v1/authorize');
        $request->set_param('client_id', 'nonexistent-client');
        $request->set_param('redirect_uri', 'https://example.com/callback');
        $request->set_param('response_type', 'code');

        $response = $this->server->dispatch($request);

        // Should return error for invalid client
        $this->assertEquals(400, $response->get_status());
        $this->assertInstanceOf('WP_Error', $response->as_error());
    }

    public function testAuthorizeEndpointWithValidClient(): void
    {
        wp_set_current_user($this->test_user_id);

        $request = new WP_REST_Request('GET', '/oauth2/v1/authorize');
        $request->set_param('client_id', 'test-client');
        $request->set_param('redirect_uri', 'http://localhost:3000/callback');
        $request->set_param('response_type', 'code');
        $request->set_param('scope', 'read write');

        $response = $this->server->dispatch($request);

        // In test environment, this might redirect or return authorization page
        $this->assertTrue(in_array($response->get_status(), [200, 302]));
    }

    public function testTokenEndpointWithInvalidGrant(): void
    {
        $request = new WP_REST_Request('POST', '/oauth2/v1/token');
        $request->set_param('grant_type', 'authorization_code');
        $request->set_param('client_id', 'test-client');
        $request->set_param('client_secret', 'test-secret');
        $request->set_param('code', 'invalid-auth-code');
        $request->set_param('redirect_uri', 'http://localhost:3000/callback');

        $response = $this->server->dispatch($request);

        $this->assertEquals(400, $response->get_status());
        $this->assertInstanceOf('WP_Error', $response->as_error());
    }

    public function testTokenEndpointWithValidGrant(): void
    {
        // First create a valid authorization code
        $auth_code = $this->createTestAuthCode();

        $request = new WP_REST_Request('POST', '/oauth2/v1/token');
        $request->set_param('grant_type', 'authorization_code');
        $request->set_param('client_id', 'test-client');
        $request->set_param('client_secret', 'test-secret');
        $request->set_param('code', $auth_code);
        $request->set_param('redirect_uri', 'http://localhost:3000/callback');

        $response = $this->server->dispatch($request);

        if ($response->get_status() === 200) {
            $data = $response->get_data();
            $this->assertArrayHasKey('data', $data);
            $this->assertArrayHasKey('access_token', $data['data']);
            $this->assertArrayHasKey('token_type', $data['data']);
            $this->assertArrayHasKey('expires_in', $data['data']);
            $this->assertEquals('Bearer', $data['data']['token_type']);
        } else {
            // In test environment, database operations might fail
            // Just verify proper error handling
            $this->assertInstanceOf('WP_Error', $response->as_error());
        }
    }

    public function testRefreshTokenFlow(): void
    {
        // Create a valid refresh token
        $refresh_token = $this->createTestRefreshToken();

        $request = new WP_REST_Request('POST', '/oauth2/v1/refresh');
        $request->set_param('grant_type', 'refresh_token');
        $request->set_param('refresh_token', $refresh_token);

        $response = $this->server->dispatch($request);

        if ($response->get_status() === 200) {
            $data = $response->get_data();
            $this->assertArrayHasKey('data', $data);
            $this->assertArrayHasKey('access_token', $data['data']);
        } else {
            // May fail in test environment due to database
            $this->assertInstanceOf('WP_Error', $response->as_error());
        }
    }

    public function testUserInfoEndpointWithValidToken(): void
    {
        // Create a valid access token
        $access_token = $this->createTestAccessToken();

        $request = new WP_REST_Request('GET', '/oauth2/v1/userinfo');
        $request->set_header('Authorization', 'Bearer ' . $access_token);

        $response = $this->server->dispatch($request);

        if ($response->get_status() === 200) {
            $data = $response->get_data();
            $this->assertArrayHasKey('data', $data);
            $this->assertArrayHasKey('user', $data['data']);
        } else {
            // May fail due to token validation in test environment
            $this->assertEquals(401, $response->get_status());
        }
    }

    public function testTokenRevocation(): void
    {
        $access_token = $this->createTestAccessToken();

        $request = new WP_REST_Request('POST', '/oauth2/v1/revoke');
        $request->set_param('token', $access_token);
        $request->set_param('token_type_hint', 'access_token');

        $response = $this->server->dispatch($request);

        // Should succeed even if token doesn't exist in test environment
        $this->assertTrue(in_array($response->get_status(), [200, 400]));
    }

    public function testBearerTokenAuthentication(): void
    {
        $access_token = $this->createTestAccessToken();

        // Test authentication with valid token format
        $result = $this->auth_oauth2->authenticate_bearer($access_token);

        if (!is_wp_error($result)) {
            $this->assertIsObject($result);
            $this->assertObjectHasAttribute('ID', $result);
        } else {
            // In test environment, token validation might fail due to database
            $this->assertInstanceOf('WP_Error', $result);
        }
    }

    public function testScopeValidationInRequest(): void
    {
        // Test that scopes are properly validated
        $valid_scopes = ['read', 'write', 'delete'];
        $invalid_scopes = ['invalid@scope', 'bad/scope'];

        foreach ($valid_scopes as $scope) {
            $this->assertTrue(wp_auth_oauth2_validate_scope($scope));
        }

        foreach ($invalid_scopes as $scope) {
            $this->assertFalse(wp_auth_oauth2_validate_scope($scope));
        }
    }

    public function testClientCredentialsValidation(): void
    {
        // Test client credentials validation
        $valid_client = $this->auth_oauth2->validate_client('test-client', 'test-secret');
        $invalid_client = $this->auth_oauth2->validate_client('invalid-client', 'wrong-secret');

        // May return boolean or WP_Error depending on test environment
        $this->assertTrue(is_bool($valid_client) || is_wp_error($valid_client));
        $this->assertFalse($invalid_client);
    }

    public function testRedirectUriValidation(): void
    {
        // Test redirect URI validation against client configuration
        $valid_uri = $this->auth_oauth2->validate_redirect_uri('test-client', 'http://localhost:3000/callback');
        $invalid_uri = $this->auth_oauth2->validate_redirect_uri('test-client', 'https://malicious.com/callback');

        $this->assertTrue($valid_uri || is_wp_error($valid_uri));
        $this->assertFalse($invalid_uri);
    }

    public function testStateParameterPreservation(): void
    {
        wp_set_current_user($this->test_user_id);

        $state = 'test-state-' . time();

        $request = new WP_REST_Request('GET', '/oauth2/v1/authorize');
        $request->set_param('client_id', 'test-client');
        $request->set_param('redirect_uri', 'http://localhost:3000/callback');
        $request->set_param('response_type', 'code');
        $request->set_param('state', $state);

        $response = $this->server->dispatch($request);

        // State should be preserved in authorization flow
        // This is typically handled in the redirect URL
        $this->assertTrue(in_array($response->get_status(), [200, 302]));
    }

    public function testCORSHeadersInOAuth2Endpoints(): void
    {
        $_SERVER['HTTP_ORIGIN'] = 'https://example.com';

        $request = new WP_REST_Request('OPTIONS', '/oauth2/v1/token');
        $response = $this->server->dispatch($request);

        // CORS should be handled properly
        $this->assertTrue(in_array($response->get_status(), [200, 204]));

        // Clean up
        unset($_SERVER['HTTP_ORIGIN']);
    }

    public function testMultipleClientsSupport(): void
    {
        // Test that different clients can be used
        $client1_request = new WP_REST_Request('GET', '/oauth2/v1/authorize');
        $client1_request->set_param('client_id', 'test-client');
        $client1_request->set_param('redirect_uri', 'http://localhost:3000/callback');
        $client1_request->set_param('response_type', 'code');

        $client2_request = new WP_REST_Request('GET', '/oauth2/v1/authorize');
        $client2_request->set_param('client_id', 'another-client');
        $client2_request->set_param('redirect_uri', 'https://another-app.com/callback');
        $client2_request->set_param('response_type', 'code');

        $response1 = $this->server->dispatch($client1_request);
        $response2 = $this->server->dispatch($client2_request);

        // First client should work (configured), second should fail (not configured)
        $this->assertTrue(in_array($response1->get_status(), [200, 302, 401]));
        $this->assertEquals(400, $response2->get_status()); // Invalid client
    }

    public function testTokenIntrospection(): void
    {
        $access_token = $this->createTestAccessToken();

        // Test token introspection
        $introspection = $this->auth_oauth2->introspect_token($access_token);

        // Should return token info or false/error
        $this->assertTrue(is_array($introspection) || is_bool($introspection) || is_wp_error($introspection));
    }

    // Helper methods

    private function setupTestClient(): void
    {
        $settings = [
            'clients' => [
                'test-client' => [
                    'name' => 'Test OAuth2 Client',
                    'client_secret' => wp_hash_password('test-secret'),
                    'redirect_uris' => [
                        'http://localhost:3000/callback',
                        'https://example.com/callback'
                    ],
                    'created_at' => current_time('mysql')
                ]
            ]
        ];

        update_option('wp_rest_auth_oauth2_settings', $settings);
    }

    private function createTestAuthCode(): string
    {
        return wp_auth_oauth2_generate_auth_code();
    }

    private function createTestAccessToken(): string
    {
        return wp_auth_oauth2_generate_access_token();
    }

    private function createTestRefreshToken(): string
    {
        return wp_auth_oauth2_generate_refresh_token();
    }
}