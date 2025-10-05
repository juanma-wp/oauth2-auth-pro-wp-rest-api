# OAuth2 Auth Pro - WP REST API

[![Unit Tests](https://github.com/juanma-wp/wp-rest-auth-oauth2/actions/workflows/unit-tests.yml/badge.svg?branch=main)](https://github.com/juanma-wp/wp-rest-auth-oauth2/actions/workflows/unit-tests.yml)
[![Integration Tests](https://github.com/juanma-wp/wp-rest-auth-oauth2/actions/workflows/integration-tests.yml/badge.svg?branch=main)](https://github.com/juanma-wp/wp-rest-auth-oauth2/actions/workflows/integration-tests.yml)
[![PHPCS](https://github.com/juanma-wp/wp-rest-auth-oauth2/actions/workflows/phpcs.yml/badge.svg?branch=main)](https://github.com/juanma-wp/wp-rest-auth-oauth2/actions/workflows/phpcs.yml)

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) [![WordPress](https://img.shields.io/badge/WordPress-%3E%3D5.6-blue.svg)](https://wordpress.org) [![PHP Version](https://img.shields.io/badge/PHP-%3E%3D7.4-blue.svg)](https://php.net)

Secure OAuth2 authentication for headless WordPress, SPAs, and mobile apps. No bloat, no upselling.


## 🚀 Why OAuth2 Auth Pro?

Unlike basic authentication plugins, OAuth2 Auth Pro implements **complete OAuth 2.0 Authorization Code flow with PKCE** following modern security best practices for decoupled WordPress applications.

### ⚡ Security Comparison

| Feature | Basic Auth Plugins | OAuth2 Auth Pro |
|---------|-------------------|--------------|
| **Authorization Flow** | Simple passwords ❌ | OAuth 2.0 + PKCE ✅ |
| **Token Lifetime** | Long or N/A ❌ | Short access tokens ✅ |
| **Refresh Tokens** | None ❌ | Secure rotation ✅ |
| **Scoped Permissions** | None ❌ | Endpoint-level scopes ✅ |
| **User Consent** | None ❌ | Built-in consent screen ✅ |
| **Multi-Client Support** | Limited ❌ | Full client management ✅ |
| **PKCE Support** | None ❌ | RFC 7636 compliant ✅ |

### 🔒 **The Problem with Basic Auth:**
- **No authorization flow** = Direct password exposure
- **No scoped access** = All-or-nothing permissions
- **No user consent** = Users can't control what apps access
- **No client management** = Can't manage multiple apps

### ✅ **OAuth2 Auth Pro Solution:**
- **Complete OAuth2 flow** = Industry-standard authorization
- **PKCE support** = Protection against authorization code interception
- **Scope-based permissions** = Granular access control per endpoint
- **User consent screen** = Users control app access
- **Multi-client support** = Manage unlimited OAuth2 clients

🔐 **Professional OAuth2 authentication for WordPress.**

## ✨ Features

- **OAuth2 Authorization Code Flow** - Complete RFC 6749 implementation
- **PKCE Support (RFC 7636)** - Protection for public clients (mobile, SPAs)
- **Scope-Based Permissions** - Automatic enforcement on REST API endpoints
- **Refresh Token Rotation** - Enhanced security with automatic rotation
- **Multi-Client Management** - Admin interface for managing OAuth2 clients
- **Built-in Consent Screen** - User authorization and consent flow
- **Clean Admin Interface** - Simple configuration in WordPress admin
- **Developer Friendly** - Clear endpoints and documentation

## 🚀 Quick Start

### 1. Install & Activate
1. Upload the plugin to `/wp-content/plugins/`
2. Activate through WordPress admin
3. Go to Settings → OAuth2 Auth Pro

### 2. Configure
1. Generate an OAuth2 Secret (or add to wp-config.php)
2. Set token expiration times
3. Create OAuth2 clients for your applications
4. Configure redirect URIs and scopes

### 3. Start Using
```javascript
// Step 1: Redirect user to authorization endpoint
const authUrl = new URL('/wp-json/oauth2/v1/authorize', 'https://your-site.com');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://your-app.com/callback');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('scope', 'read write');
authUrl.searchParams.set('state', 'random-state-value');
authUrl.searchParams.set('code_challenge', 'base64-url-encoded-challenge');
authUrl.searchParams.set('code_challenge_method', 'S256');

window.location.href = authUrl.toString();

// Step 2: Handle callback and exchange code for tokens
const code = new URLSearchParams(window.location.search).get('code');

const response = await fetch('/wp-json/oauth2/v1/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'https://your-app.com/callback',
        client_id: 'your-client-id',
        code_verifier: 'original-code-verifier' // PKCE verifier
    })
});

const { access_token, refresh_token } = await response.json();

// Step 3: Use access token for API calls
const posts = await fetch('/wp-json/wp/v2/posts', {
    headers: { 'Authorization': `Bearer ${access_token}` }
});
```

## 📍 Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/wp-json/oauth2/v1/authorize` | Authorization endpoint (user consent) |
| `POST` | `/wp-json/oauth2/v1/token` | Token endpoint (exchange code/refresh) |
| `POST` | `/wp-json/oauth2/v1/revoke` | Token revocation endpoint |
| `GET` | `/wp-json/oauth2/v1/userinfo` | Get user information with token |
| `GET` | `/wp-json/oauth2/v1/scopes` | List available scopes |

## 🔒 Security

- **OAuth 2.0 Authorization Code Flow** - Industry standard authorization
- **PKCE Support** - Protection against authorization code interception (RFC 7636)
- **Scope-Based Access Control** - Granular permissions per endpoint
- **Refresh Token Rotation** - Tokens automatically rotate on use
- **Secure Token Storage** - Hashed tokens in database
- **IP & User Agent Tracking** - Additional security metadata
- **Configurable Expiration** - Set custom token lifetimes

## ⚙️ Configuration

### Via wp-config.php (Recommended for production)
```php
define('WP_OAUTH2_SECRET', 'your-super-secret-key-here');
define('WP_OAUTH2_ACCESS_TTL', 3600);      // 1 hour
define('WP_OAUTH2_REFRESH_TTL', 2592000);  // 30 days
```

### Via WordPress Admin
Go to **Settings → OAuth2 Auth Pro** to configure:
- OAuth2 Secret Key
- Token expiration times
- OAuth2 clients and redirect URIs
- Scopes and permissions
- Debug logging

## 💡 Use Cases

Perfect for:
- **Single Page Applications** (React, Vue, Angular)
- **Mobile Applications** (iOS, Android)
- **Third-Party Integrations** (OAuth2 authorization)
- **Headless WordPress** (Decoupled architecture)
- **Multi-tenant Applications** (Client management)

## 🔄 OAuth2 Flow

1. **Authorization Request** → User redirects to authorize endpoint
2. **User Consent** → User approves scopes and permissions
3. **Authorization Code** → User redirected back with code
4. **Token Exchange** → Exchange code for access + refresh tokens
5. **API Calls** → Use access token in Authorization header
6. **Token Refresh** → Use refresh token to get new access token
7. **Token Revocation** → Revoke tokens when done

## 🛠️ Scopes

Available scopes for granular access control:

| Scope | Description | Required Capability |
|-------|-------------|-------------------|
| `read` | View posts, pages, and profile | `read` |
| `write` | Create and edit content | `edit_posts` |
| `delete` | Delete posts and pages | `delete_posts` |
| `upload_files` | Upload and manage media | `upload_files` |
| `manage_users` | View and manage users | `list_users` |
| `manage_categories` | Manage categories and tags | `manage_categories` |
| `moderate_comments` | Moderate comments | `moderate_comments` |
| `edit_theme` | Modify theme settings | `edit_theme_options` |
| `manage_plugins` | Manage plugins | `activate_plugins` |
| `manage_options` | Site settings access | `manage_options` |

## 🔐 PKCE Support (For Mobile & SPA Apps)

PKCE (Proof Key for Code Exchange) adds security for public clients that cannot securely store a client secret.

### JavaScript Example
```javascript
// Generate code verifier and challenge
function generateCodeVerifier() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return base64UrlEncode(new Uint8Array(hash));
}

const codeVerifier = generateCodeVerifier();
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Store verifier for later use
sessionStorage.setItem('code_verifier', codeVerifier);

// Authorization request with PKCE
const authUrl = `https://your-site.com/wp-json/oauth2/v1/authorize?` +
    `client_id=your-client-id&` +
    `redirect_uri=https://your-app.com/callback&` +
    `response_type=code&` +
    `scope=read write&` +
    `code_challenge=${codeChallenge}&` +
    `code_challenge_method=S256`;

window.location.href = authUrl;

// Exchange code for tokens (no client_secret needed!)
const tokenResponse = await fetch('https://your-site.com/wp-json/oauth2/v1/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        grant_type: 'authorization_code',
        client_id: 'your-client-id',
        code: authCode,
        redirect_uri: 'https://your-app.com/callback',
        code_verifier: storedVerifier  // Proves we started the flow
    })
});
```

## 🧪 Testing (wp-env)

Run tests using the NPM scripts which leverage wp-env:

```bash
# Start environment
npm run env:start

# Run tests
npm run test

# Stop environment
npm run env:stop
```

## ❓ Need Simpler Authentication?

This plugin provides full OAuth2 authorization. If you need:
- Simple JWT authentication
- Stateless tokens only
- No authorization flow
- Basic REST API auth

Check out our companion plugin: **JWT Auth Pro - Secure Refresh Tokens**

## 📝 Requirements

- WordPress 5.6+
- PHP 7.4+
- HTTPS (recommended for production)

## 📄 License

GPL v2 or later

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📚 References

- **OAuth 2.0 Authorization Framework (RFC 6749)**: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- **OAuth 2.0 PKCE (RFC 7636)**: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- **OAuth 2.0 Token Revocation (RFC 7009)**: [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)
- **OAuth 2.0 Security Best Current Practice (IETF)**: [datatracker draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- **OAuth 2.0 for Browser-Based Apps (IETF)**: [datatracker draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- **OAuth 2.0 Scope Syntax (RFC 6749 Section 3.3)**: [RFC 6749 Section 3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3)

---

**Professional. Secure. OAuth2.** 🔐
