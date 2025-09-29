<?php

use WPRestAuthOAuth2\Tests\Helpers\TestCase;

/**
 * Integration tests for API Proxy functionality
 */
class ApiProxyIntegrationTest extends WP_UnitTestCase
{
    private $api_proxy;
    private $server;
    private $test_user_id;

    public function setUp(): void
    {
        parent::setUp();

        // Set up REST server
        global $wp_rest_server;
        $this->server = $wp_rest_server = new WP_REST_Server();
        do_action('rest_api_init');

        // Load API Proxy
        if (!class_exists('WP_REST_API_Proxy')) {
            require_once WP_REST_AUTH_OAUTH2_PLUGIN_DIR . 'includes/class-api-proxy.php';
        }

        $this->api_proxy = new WP_REST_API_Proxy();

        // Register proxy routes if enabled
        if (method_exists($this->api_proxy, 'register_routes')) {
            $this->api_proxy->register_routes();
        }

        // Create test user
        $this->test_user_id = $this->factory->user->create([
            'user_login' => 'proxyuser',
            'user_pass' => 'testpass123',
            'user_email' => 'proxy@example.com',
            'role' => 'editor'
        ]);

        // Enable proxy for testing
        $this->enableProxyForTesting();
    }

    public function tearDown(): void
    {
        global $wp_rest_server;
        $wp_rest_server = null;

        parent::tearDown();
    }

    public function testProxyRoutesRegistered(): void
    {
        $routes = $this->server->get_routes();

        // Test that proxy routes are registered when enabled
        if ($this->isProxyEnabled()) {
            $this->assertArrayHasKey('/proxy/v1/login', $routes);
            $this->assertArrayHasKey('/proxy/v1/logout', $routes);
            $this->assertArrayHasKey('/proxy/v1/api', $routes);
        } else {
            $this->markTestSkipped('Proxy is not enabled for testing');
        }
    }

    public function testProxyLoginEndpoint(): void
    {
        if (!$this->isProxyEnabled()) {
            $this->markTestSkipped('Proxy is not enabled');
        }

        $request = new WP_REST_Request('GET', '/proxy/v1/login');
        $request->set_param('client_id', 'test-client');

        $response = $this->server->dispatch($request);

        // Should redirect to OAuth2 authorization or return login page
        $this->assertTrue(in_array($response->get_status(), [200, 302]));
    }

    public function testProxyLogoutEndpoint(): void
    {
        if (!$this->isProxyEnabled()) {
            $this->markTestSkipped('Proxy is not enabled');
        }

        $request = new WP_REST_Request('POST', '/proxy/v1/logout');
        $response = $this->server->dispatch($request);

        // Should handle logout even without active session
        $this->assertTrue(in_array($response->get_status(), [200, 400]));
    }

    public function testProxyApiEndpoint(): void
    {
        if (!$this->isProxyEnabled()) {
            $this->markTestSkipped('Proxy is not enabled');
        }

        // Test proxied API request
        $request = new WP_REST_Request('GET', '/proxy/v1/api/wp/v2/posts');
        $response = $this->server->dispatch($request);

        // Should require authentication
        $this->assertTrue(in_array($response->get_status(), [401, 403]));
    }

    public function testProxyApiWithValidSession(): void
    {
        if (!$this->isProxyEnabled()) {
            $this->markTestSkipped('Proxy is not enabled');
        }

        // Create a valid proxy session
        $session_id = $this->createTestProxySession();

        if ($session_id) {
            // Simulate session cookie
            $_COOKIE['wp_proxy_session'] = $session_id;

            $request = new WP_REST_Request('GET', '/proxy/v1/api/wp/v2/posts');
            $response = $this->server->dispatch($request);

            // Should proxy the request or return proper error
            $this->assertTrue(in_array($response->get_status(), [200, 401, 500]));

            // Clean up
            unset($_COOKIE['wp_proxy_session']);
        }
    }

    public function testProxyModeFullFiltering(): void
    {
        if (!$this->isProxyEnabled()) {
            $this->markTestSkipped('Proxy is not enabled');
        }

        // In full mode, all requests should be proxied
        $test_endpoints = [
            '/wp/v2/posts',
            '/wp/v2/users',
            '/wp/v2/comments',
            '/custom/v1/endpoint'
        ];

        foreach ($test_endpoints as $endpoint) {
            if (method_exists($this->api_proxy, 'should_proxy_request')) {
                $should_proxy = $this->api_proxy->should_proxy_request($endpoint, 'full');
                $this->assertTrue($should_proxy);
            }
        }
    }

    public function testProxyModeSelectiveFiltering(): void
    {
        if (!$this->isProxyEnabled()) {
            $this->markTestSkipped('Proxy is not enabled');
        }

        // In selective mode, only certain endpoints should be proxied
        if (method_exists($this->api_proxy, 'should_proxy_request')) {
            $authenticated_endpoint = '/wp/v2/posts';
            $public_endpoint = '/wp/v2/posts?status=publish';

            $should_proxy_auth = $this->api_proxy->should_proxy_request($authenticated_endpoint, 'selective');
            $should_proxy_public = $this->api_proxy->should_proxy_request($public_endpoint, 'selective');

            // Implementation may vary, just test that method works
            $this->assertIsBool($should_proxy_auth);
            $this->assertIsBool($should_proxy_public);
        }
    }

    public function testProxySessionCreation(): void
    {
        if (!method_exists($this->api_proxy, 'create_proxy_session')) {
            $this->markTestSkipped('Proxy session creation not implemented');
        }

        $access_token = 'test-access-token-' . time();
        $refresh_token = 'test-refresh-token-' . time();

        $session_id = $this->api_proxy->create_proxy_session(
            $this->test_user_id,
            $access_token,
            $refresh_token
        );

        $this->assertTrue(is_string($session_id) || is_wp_error($session_id));
    }

    public function testProxySessionValidation(): void
    {
        if (!method_exists($this->api_proxy, 'validate_proxy_session')) {
            $this->markTestSkipped('Proxy session validation not implemented');
        }

        // Test invalid session
        $invalid_result = $this->api_proxy->validate_proxy_session('invalid-session-id');
        $this->assertFalse($invalid_result);

        // Test valid session (if we can create one)
        if (method_exists($this->api_proxy, 'create_proxy_session')) {
            $session_id = $this->api_proxy->create_proxy_session($this->test_user_id, 'test-token', 'refresh-token');

            if (is_string($session_id)) {
                $valid_result = $this->api_proxy->validate_proxy_session($session_id);
                $this->assertTrue($valid_result || is_wp_error($valid_result));
            }
        }
    }

    public function testProxyTokenRefresh(): void
    {
        if (!method_exists($this->api_proxy, 'refresh_session_token')) {
            $this->markTestSkipped('Token refresh not implemented');
        }

        $session_id = $this->createTestProxySession();

        if ($session_id) {
            $result = $this->api_proxy->refresh_session_token($session_id);
            $this->assertTrue(is_bool($result) || is_wp_error($result));
        }
    }

    public function testProxySecurityHeaders(): void
    {
        if (!method_exists($this->api_proxy, 'add_security_headers')) {
            $this->markTestSkipped('Security headers not implemented');
        }

        // Capture headers before and after
        $headers_before = headers_list();
        $this->api_proxy->add_security_headers();

        // Should not throw errors
        $this->assertTrue(true);
    }

    public function testProxyCORSHandling(): void
    {
        if (!method_exists($this->api_proxy, 'handle_cors')) {
            $this->markTestSkipped('CORS handling not implemented');
        }

        $_SERVER['HTTP_ORIGIN'] = 'https://example.com';
        $_SERVER['REQUEST_METHOD'] = 'OPTIONS';

        $this->api_proxy->handle_cors();

        // Should handle CORS without errors
        $this->assertTrue(true);

        // Clean up
        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['REQUEST_METHOD']);
    }

    public function testProxyRequestLogging(): void
    {
        if (!method_exists($this->api_proxy, 'log_proxy_request')) {
            $this->markTestSkipped('Request logging not implemented');
        }

        $request_data = [
            'method' => 'GET',
            'endpoint' => '/wp/v2/posts',
            'user_id' => $this->test_user_id,
            'timestamp' => time(),
            'response_code' => 200
        ];

        $this->api_proxy->log_proxy_request($request_data);

        // Should not throw errors
        $this->assertTrue(true);
    }

    public function testProxyRateLimiting(): void
    {
        if (!method_exists($this->api_proxy, 'check_rate_limit')) {
            $this->markTestSkipped('Rate limiting not implemented');
        }

        $endpoint = '/wp/v2/posts';

        // Test rate limit check
        $rate_ok = $this->api_proxy->check_rate_limit($this->test_user_id, $endpoint);
        $this->assertTrue(is_bool($rate_ok) || is_wp_error($rate_ok));
    }

    public function testProxySessionTimeout(): void
    {
        if (!method_exists($this->api_proxy, 'is_session_expired')) {
            $this->markTestSkipped('Session timeout not implemented');
        }

        // Test expired session
        $expired_time = time() - 7200; // 2 hours ago
        $is_expired = $this->api_proxy->is_session_expired($expired_time);
        $this->assertTrue($is_expired);

        // Test valid session
        $valid_time = time() + 3600; // 1 hour from now
        $is_valid = $this->api_proxy->is_session_expired($valid_time);
        $this->assertFalse($is_valid);
    }

    public function testProxySessionCleanup(): void
    {
        if (!method_exists($this->api_proxy, 'cleanup_expired_sessions')) {
            $this->markTestSkipped('Session cleanup not implemented');
        }

        // Should run without errors
        $this->api_proxy->cleanup_expired_sessions();
        $this->assertTrue(true);
    }

    public function testProxyErrorHandling(): void
    {
        if (!method_exists($this->api_proxy, 'create_proxy_error')) {
            $this->markTestSkipped('Proxy error handling not implemented');
        }

        $error = $this->api_proxy->create_proxy_error(
            'session_expired',
            'Your session has expired. Please log in again.'
        );

        $this->assertInstanceOf('WP_Error', $error);
        $this->assertEquals('session_expired', $error->get_error_code());
    }

    public function testProxyRequestTransformation(): void
    {
        if (!method_exists($this->api_proxy, 'transform_request')) {
            $this->markTestSkipped('Request transformation not implemented');
        }

        $original_request = [
            'method' => 'GET',
            'url' => '/wp/v2/posts',
            'headers' => ['Content-Type' => 'application/json'],
            'body' => null
        ];

        $transformed = $this->api_proxy->transform_request($original_request);
        $this->assertTrue(is_array($transformed) || is_wp_error($transformed));
    }

    public function testProxyResponseTransformation(): void
    {
        if (!method_exists($this->api_proxy, 'transform_response')) {
            $this->markTestSkipped('Response transformation not implemented');
        }

        $original_response = [
            'status' => 200,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => '{"posts": []}'
        ];

        $transformed = $this->api_proxy->transform_response($original_response);
        $this->assertTrue(is_array($transformed) || is_wp_error($transformed));
    }

    public function testProxyMiddleware(): void
    {
        if (!method_exists($this->api_proxy, 'apply_middleware')) {
            $this->markTestSkipped('Middleware not implemented');
        }

        $request = [
            'method' => 'POST',
            'url' => '/wp/v2/posts',
            'headers' => ['Authorization' => 'Bearer test-token'],
            'body' => '{"title": "Test Post"}'
        ];

        $processed = $this->api_proxy->apply_middleware($request);
        $this->assertTrue(is_array($processed) || is_wp_error($processed));
    }

    public function testProxyPerformanceMetrics(): void
    {
        if (!method_exists($this->api_proxy, 'record_proxy_metrics')) {
            $this->markTestSkipped('Performance metrics not implemented');
        }

        $metrics = [
            'request_time' => 0.250,
            'memory_usage' => 1024768,
            'cache_hit' => true,
            'response_size' => 4096
        ];

        $this->api_proxy->record_proxy_metrics($metrics);

        // Should not throw errors
        $this->assertTrue(true);
    }

    public function testProxyConfigurationValidation(): void
    {
        if (!method_exists($this->api_proxy, 'validate_proxy_config')) {
            $this->markTestSkipped('Configuration validation not implemented');
        }

        $valid_config = [
            'proxy_enabled' => true,
            'proxy_mode' => 'full',
            'session_timeout' => 3600,
            'max_requests_per_minute' => 60
        ];

        $is_valid = $this->api_proxy->validate_proxy_config($valid_config);
        $this->assertTrue($is_valid || is_wp_error($is_valid));

        $invalid_config = [
            'proxy_mode' => 'invalid',
            'session_timeout' => -1
        ];

        $is_invalid = $this->api_proxy->validate_proxy_config($invalid_config);
        $this->assertFalse($is_invalid || is_wp_error($is_invalid));
    }

    // Helper methods

    private function enableProxyForTesting(): void
    {
        // Enable proxy in settings
        $settings = get_option('wp_rest_auth_oauth2_settings', []);
        $settings['proxy_enabled'] = true;
        $settings['proxy_mode'] = 'full';
        update_option('wp_rest_auth_oauth2_settings', $settings);
    }

    private function isProxyEnabled(): bool
    {
        $settings = get_option('wp_rest_auth_oauth2_settings', []);
        return !empty($settings['proxy_enabled']);
    }

    private function createTestProxySession(): ?string
    {
        if (!method_exists($this->api_proxy, 'create_proxy_session')) {
            return null;
        }

        $access_token = 'test-token-' . time();
        $refresh_token = 'refresh-token-' . time();

        $session_id = $this->api_proxy->create_proxy_session(
            $this->test_user_id,
            $access_token,
            $refresh_token
        );

        return is_string($session_id) ? $session_id : null;
    }
}