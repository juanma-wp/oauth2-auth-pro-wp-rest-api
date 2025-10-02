<?php

/**
 * Integration tests for OAuth2 Helper functions with WordPress
 */
class HelpersIntegrationTest extends WP_UnitTestCase
{
    private $test_user_id;

    public function setUp(): void
    {
        parent::setUp();

        // Create test user with specific capabilities
        $this->test_user_id = $this->factory->user->create([
            'user_login' => 'oauth2helperuser',
            'user_pass' => 'testpass123',
            'user_email' => 'helpertest@example.com',
            'first_name' => 'OAuth2',
            'last_name' => 'Helper',
            'display_name' => 'OAuth2 Helper User',
            'role' => 'editor'
        ]);
    }

    public function testUserScopeAccess(): void
    {
        $user = get_user_by('id', $this->test_user_id);
        $this->assertInstanceOf('WP_User', $user);

        // Editor should have read, write, delete capabilities
        $this->assertTrue(wp_auth_oauth2_user_can_access_scope($user, 'read'));
        $this->assertTrue(wp_auth_oauth2_user_can_access_scope($user, 'write'));
        $this->assertTrue(wp_auth_oauth2_user_can_access_scope($user, 'delete'));
        $this->assertTrue(wp_auth_oauth2_user_can_access_scope($user, 'upload_files'));

        // Editor should NOT have admin capabilities
        $this->assertFalse(wp_auth_oauth2_user_can_access_scope($user, 'manage_options'));
        $this->assertFalse(wp_auth_oauth2_user_can_access_scope($user, 'manage_plugins'));

        // Test invalid scope
        $this->assertFalse(wp_auth_oauth2_user_can_access_scope($user, 'nonexistent_scope'));
    }

    public function testUserDataFormatting(): void
    {
        $user = get_user_by('id', $this->test_user_id);
        $this->assertInstanceOf('WP_User', $user);

        // Test basic user data formatting
        $user_data = wp_auth_oauth2_format_user_data($user, false);

        $this->assertIsArray($user_data);
        $this->assertEquals($this->test_user_id, $user_data['id']);
        $this->assertEquals('oauth2helperuser', $user_data['username']);
        $this->assertEquals('helpertest@example.com', $user_data['email']);
        $this->assertEquals('OAuth2 Helper User', $user_data['display_name']);
        $this->assertEquals('OAuth2', $user_data['first_name']);
        $this->assertEquals('Helper', $user_data['last_name']);
        $this->assertContains('editor', $user_data['roles']);
        $this->assertArrayHasKey('avatar_url', $user_data);

        // Should NOT include sensitive data
        $this->assertArrayNotHasKey('capabilities', $user_data);
        $this->assertArrayNotHasKey('meta', $user_data);

        // Test with sensitive data included
        $user_data_sensitive = wp_auth_oauth2_format_user_data($user, true);

        $this->assertArrayHasKey('capabilities', $user_data_sensitive);
        $this->assertArrayHasKey('meta', $user_data_sensitive);
    }

    public function testCORSOriginValidation(): void
    {
        // Set up test CORS origins
        $settings = [
            'general' => [
                'cors_allowed_origins' => "https://example.com\nhttps://app.example.com\nhttp://localhost:3000"
            ]
        ];
        update_option('wp_rest_auth_oauth2_general_settings', $settings['general']);

        // Test valid origins
        $this->assertTrue(wp_auth_oauth2_is_valid_origin('https://example.com'));
        $this->assertTrue(wp_auth_oauth2_is_valid_origin('https://app.example.com'));
        $this->assertTrue(wp_auth_oauth2_is_valid_origin('http://localhost:3000'));

        // Test invalid origins
        $this->assertFalse(wp_auth_oauth2_is_valid_origin('https://malicious.com'));
        $this->assertFalse(wp_auth_oauth2_is_valid_origin('http://example.com')); // http vs https
        $this->assertFalse(wp_auth_oauth2_is_valid_origin(''));

        // Test wildcard (allow all)
        $settings['general']['cors_allowed_origins'] = '*';
        update_option('wp_rest_auth_oauth2_general_settings', $settings['general']);

        $this->assertTrue(wp_auth_oauth2_is_valid_origin('https://anything.com'));
        $this->assertTrue(wp_auth_oauth2_is_valid_origin('http://localhost:8080'));

        // Clean up
        delete_option('wp_rest_auth_oauth2_general_settings');
    }

    public function testTransientStorageForAuthCodes(): void
    {
        // Test authorization code storage using WordPress transients
        $auth_code = wp_auth_oauth2_generate_auth_code();
        $auth_data = [
            'client_id' => 'test-client',
            'user_id' => $this->test_user_id,
            'redirect_uri' => 'http://localhost:3000/callback',
            'scopes' => ['read', 'write'],
            'expires_at' => time() + 600
        ];

        // Store the auth code
        set_transient('oauth2_auth_code_' . $auth_code, $auth_data, 600);

        // Retrieve the auth code
        $retrieved_data = get_transient('oauth2_auth_code_' . $auth_code);

        $this->assertIsArray($retrieved_data);
        $this->assertEquals('test-client', $retrieved_data['client_id']);
        $this->assertEquals($this->test_user_id, $retrieved_data['user_id']);
        $this->assertEquals(['read', 'write'], $retrieved_data['scopes']);

        // Clean up
        delete_transient('oauth2_auth_code_' . $auth_code);
    }

    public function testPasswordHashing(): void
    {
        // Test WordPress password hashing for client secrets
        $client_secret = 'test-client-secret-password';
        $hashed_secret = wp_hash_password($client_secret);

        $this->assertIsString($hashed_secret);
        $this->assertNotEquals($client_secret, $hashed_secret);

        // Verify password
        $is_valid = wp_check_password($client_secret, $hashed_secret);
        $this->assertTrue($is_valid);

        // Verify wrong password fails
        $is_invalid = wp_check_password('wrong-password', $hashed_secret);
        $this->assertFalse($is_invalid);
    }

    public function testFilterHooks(): void
    {
        // Test that filter hooks work for user data formatting
        add_filter('wp_auth_oauth2_user_data', function($user_data, $user) {
            $user_data['custom_field'] = 'custom_value';
            return $user_data;
        }, 10, 2);

        $user = get_user_by('id', $this->test_user_id);
        $user_data = wp_auth_oauth2_format_user_data($user, false);

        $this->assertArrayHasKey('custom_field', $user_data);
        $this->assertEquals('custom_value', $user_data['custom_field']);

        // Clean up
        remove_all_filters('wp_auth_oauth2_user_data');
    }

    public function testAvailableScopesFilter(): void
    {
        // Test that available scopes can be filtered
        add_filter('wp_auth_oauth2_available_scopes', function($scopes) {
            $scopes['custom_scope'] = 'Custom application scope';
            return $scopes;
        });

        $scopes = wp_auth_oauth2_get_available_scopes();

        $this->assertArrayHasKey('custom_scope', $scopes);
        $this->assertEquals('Custom application scope', $scopes['custom_scope']);

        // Clean up
        remove_all_filters('wp_auth_oauth2_available_scopes');
    }

    public function testCORSOriginsFilter(): void
    {
        // Set up basic CORS origins
        $settings = [
            'general' => [
                'cors_allowed_origins' => "https://example.com"
            ]
        ];
        update_option('wp_rest_auth_oauth2_general_settings', $settings['general']);

        // Add filter to modify allowed origins
        add_filter('wp_auth_oauth2_cors_origins', function($origins) {
            $origins[] = 'https://filtered-origin.com';
            return $origins;
        });

        // Test filtered origin is now allowed
        $this->assertTrue(wp_auth_oauth2_is_valid_origin('https://filtered-origin.com'));

        // Clean up
        remove_all_filters('wp_auth_oauth2_cors_origins');
        delete_option('wp_rest_auth_oauth2_general_settings');
    }
}
