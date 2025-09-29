# OAuth2 Plugin Testing

This directory contains the comprehensive test suite for the WP REST Auth OAuth2 plugin.

## Prerequisites

- Node.js 16+ and npm 8+
- PHP 7.4+ with Composer
- Docker and Docker Compose (for wp-env)

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   composer install
   ```

2. **Start the test environment:**
   ```bash
   npm run env:start
   # or
   composer run env:start
   ```

## Running Tests

### Using wp-env (Recommended)
```bash
# All tests
composer test
# or
npm run test

# Unit tests only
composer test-unit

# Integration tests only
composer test-integration

# OAuth2 specific tests
composer test-oauth2

# API Proxy tests
composer test-proxy

# Local tests (without wp-env)
composer test-local
```

### Manual phpunit
```bash
# Make sure wp-env is running first
npm run env:start

# Run tests
./vendor/bin/phpunit --configuration phpunit.xml
```

## Test Structure

```
tests/
├── bootstrap.php                      # Standard PHPUnit bootstrap
├── bootstrap-wp-env.php               # wp-env specific bootstrap
├── helpers/
│   └── TestCase.php                  # Base test case with OAuth2 utilities
├── unit/                             # Unit tests
│   ├── HelpersTest.php              # OAuth2 helper functions tests
│   ├── OAuth2AuthTest.php           # OAuth2 authentication tests
│   └── ApiProxyTest.php             # API Proxy functionality tests
├── integration/                     # Integration tests
│   ├── OAuth2FlowIntegrationTest.php # Complete OAuth2 flow tests
│   └── ApiProxyIntegrationTest.php   # API Proxy integration tests
└── README.md                        # This file
```

## Test Environment

- **WordPress**: Latest stable version
- **PHP**: 8.1 (configurable in .wp-env.json)
- **Database**: MySQL (via Docker)
- **Ports**:
  - Development: 8890
  - Tests: 8891

## Configuration

The test environment is configured via `.wp-env.json`:

```json
{
  "core": "WordPress/WordPress#6.4",
  "phpVersion": "8.1",
  "plugins": ["."],
  "config": {
    "WP_DEBUG": true,
    "WP_OAUTH2_SECRET": "test-oauth2-secret"
  },
  "port": 8890,
  "testsPort": 8891
}
```

## Environment Management

```bash
# Start environment
npm run env:start

# Stop environment
npm run env:stop

# Restart environment
npm run env:restart

# Clean environment (reset database)
npm run env:clean

# Destroy environment (remove containers)
npm run env:destroy
```

## Test Categories

### Unit Tests

#### HelpersTest
- OAuth2 token generation and validation
- Scope parsing and validation
- Client ID sanitization
- Redirect URI validation
- Error response formatting

#### OAuth2AuthTest
- OAuth2 authentication flow
- Client credential validation
- Token storage and retrieval
- Scope handling and permissions
- Authorization code management

#### ApiProxyTest
- Proxy session management
- Request forwarding
- Security headers
- CORS handling
- Rate limiting
- Performance metrics

### Integration Tests

#### OAuth2FlowIntegrationTest
- Complete authorization code flow
- Token exchange and refresh
- User info endpoint
- Multi-client support
- Scope validation in requests

#### ApiProxyIntegrationTest
- Proxy route registration
- Session-based authentication
- API request proxying
- Security and CORS integration
- Error handling

## Writing Tests

### OAuth2-Specific Test Utilities

The base test case provides OAuth2-specific utilities:

```php
<?php
use WPRestAuthOAuth2\Tests\Helpers\TestCase;

class MyOAuth2Test extends TestCase
{
    public function testOAuth2Client(): void
    {
        $client = $this->createTestOAuth2Client('my-client');
        $this->assertArrayHasKey('client_id', $client);
    }

    public function testAccessToken(): void
    {
        $token = $this->createTestOAuth2Token(123, ['read', 'write']);
        $this->assertIsString($token);
    }
}
```

### Mock Data Creation

```php
// Create test OAuth2 client
$client = $this->createTestOAuth2Client('test-client');

// Create test access token
$token = $this->createTestOAuth2Token($user_id, ['read', 'write']);

// Create test authorization code
$code = $this->createTestAuthCode($user_id, 'test-client');

// Create proxy session
$session = $this->createMockProxySession($user_id);
```

## OAuth2 Flow Testing

### Authorization Endpoint
```php
$request = new WP_REST_Request('GET', '/oauth2/v1/authorize');
$request->set_param('client_id', 'test-client');
$request->set_param('redirect_uri', 'http://localhost:3000/callback');
$request->set_param('response_type', 'code');
$request->set_param('scope', 'read write');

$response = $this->server->dispatch($request);
```

### Token Exchange
```php
$request = new WP_REST_Request('POST', '/oauth2/v1/token');
$request->set_param('grant_type', 'authorization_code');
$request->set_param('client_id', 'test-client');
$request->set_param('client_secret', 'test-secret');
$request->set_param('code', $auth_code);

$response = $this->server->dispatch($request);
```

## API Proxy Testing

### Proxy Session
```php
// Create proxy session
$session_id = $this->api_proxy->create_proxy_session(
    $user_id,
    $access_token,
    $refresh_token
);

// Test proxied request
$_COOKIE['wp_proxy_session'] = $session_id;
$request = new WP_REST_Request('GET', '/proxy/v1/api/wp/v2/posts');
$response = $this->server->dispatch($request);
```

## Debugging

1. **Enable debug mode:**
   ```bash
   wp-env run tests-wordpress wp config set WP_DEBUG true
   wp-env run tests-wordpress wp config set WP_DEBUG_LOG true
   ```

2. **View logs:**
   ```bash
   wp-env logs tests
   ```

3. **Access test sites:**
   - Development: http://localhost:8890
   - Tests: http://localhost:8891

4. **Database access:**
   ```bash
   wp-env run tests-wordpress wp db cli
   ```

## Performance Testing

The test suite includes performance metrics:

```php
$metrics = [
    'request_time' => 0.250,
    'memory_usage' => 1024768,
    'cache_hit' => true,
    'response_size' => 4096
];

$this->api_proxy->record_proxy_metrics($metrics);
```

## Security Testing

Tests include security validations:
- Client credential validation
- Token expiration handling
- Scope permission checking
- CORS validation
- Rate limiting
- Session security

## Continuous Integration

Example GitHub Actions workflow:

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: |
          npm install
          composer install
      - name: Start wp-env
        run: npm run env:start
      - name: Run tests
        run: composer test
```