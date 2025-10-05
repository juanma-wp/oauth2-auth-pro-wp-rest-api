# Security Measures

This document explains the comprehensive security measures implemented in **OAuth2 Auth Pro - WP REST API** to protect your WordPress application and user data.

## Table of Contents

1. [OAuth 2.0 Authorization Code Flow](#oauth-20-authorization-code-flow)
2. [PKCE (Proof Key for Code Exchange)](#pkce-proof-key-for-code-exchange)
3. [Refresh Token Security](#refresh-token-security)
4. [Scope-Based Access Control](#scope-based-access-control)
5. [Token Storage and Hashing](#token-storage-and-hashing)
6. [Security Best Practices](#security-best-practices)
7. [Threat Model](#threat-model)

---

## OAuth 2.0 Authorization Code Flow

The plugin implements the **OAuth 2.0 Authorization Code Flow** (RFC 6749), which is the industry-standard authorization framework for web and mobile applications.

### How It Works

```
1. Client redirects user to authorization endpoint
2. User authenticates with WordPress
3. User grants consent for requested scopes
4. Server issues authorization code (5-minute expiry)
5. Client exchanges code for access + refresh tokens
6. Client uses access token for API requests
```

### Security Benefits

- **Separation of concerns**: Authorization code is exchanged server-side, not exposed to the browser
- **Short-lived codes**: Authorization codes expire in 5 minutes (configurable)
- **One-time use**: Authorization codes are deleted immediately after use
- **Redirect URI validation**: Prevents code interception attacks

**Implementation**: [`includes/class-auth-oauth2.php:799-947`](../includes/class-auth-oauth2.php#L799-L947)

---

## PKCE (Proof Key for Code Exchange)

PKCE (RFC 7636) adds an additional layer of security specifically designed for **public clients** (SPAs, mobile apps, CLI tools) that cannot securely store a client secret.

### The Problem Without PKCE

If an attacker intercepts the authorization code (e.g., through app URI hijacking, malicious browser extensions, or network interception), they can exchange it for an access token at the token endpoint, since there's no way to verify that the same client making the token request is the one that initiated the authorization.

### How PKCE Solves This

1. **Code Verifier**: Client generates a cryptographically random string (43-128 characters) and keeps it secret
2. **Code Challenge**: Client creates a SHA256 hash of the code verifier and sends it with the authorization request
3. **Server Stores Challenge**: The authorization server stores the code challenge with the authorization code
4. **Verification**: When exchanging the code for a token, the client must provide the original code verifier
5. **Server Validates**: The server hashes the provided verifier and compares it to the stored challenge

### Why This Works

Even if an attacker intercepts the authorization code, they **cannot** exchange it for a token because:

- They don't have the original code verifier (it never left the client)
- They can't derive the verifier from the challenge (SHA256 is a one-way hash)
- The authorization server rejects any token request without the correct verifier

### Implementation Details

**Code Challenge Generation** (Client-side):
```javascript
// Generate random verifier
const codeVerifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

// Create SHA256 challenge
const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
const codeChallenge = base64UrlEncode(new Uint8Array(hash));
```

**Server-side Validation**: [`includes/class-auth-oauth2.php:836-857`](../includes/class-auth-oauth2.php#L836-L857)

```php
// Validate code_verifier against stored code_challenge
if (!wp_auth_oauth2_verify_code_challenge($code_verifier, $code_challenge, 'S256')) {
    return wp_auth_oauth2_error_response('invalid_grant', 'Invalid code_verifier', 400);
}
```

**PKCE Helper Functions**: [`includes/helpers.php`](../includes/helpers.php)

### When to Use PKCE

- ✅ **Single Page Applications (SPAs)** - React, Vue, Angular
- ✅ **Mobile Applications** - iOS, Android, React Native
- ✅ **CLI Tools** - Command-line OAuth2 clients
- ✅ **Desktop Applications** - Electron apps
- ❌ **Server-side applications** - Can use client_secret instead (but PKCE doesn't hurt)

---

## Refresh Token Security

Refresh tokens are long-lived credentials (30 days by default) that allow clients to obtain new access tokens without requiring the user to re-authenticate. **Protecting refresh tokens is critical** since they're the most sensitive credential in OAuth2.

### Storage Method: HttpOnly Cookies

The plugin stores refresh tokens in **HttpOnly, Secure cookies** with restricted paths.

**Implementation**: [`includes/class-auth-oauth2.php:927-934`](../includes/class-auth-oauth2.php#L927-L934)

```php
wp_auth_oauth2_set_cookie(
    'wp_oauth2_refresh_token',
    $refresh_token,
    $refresh_expires,
    '/wp-json/oauth2/v1/',  // Path restriction
    true,   // HttpOnly flag
    true    // Secure flag (HTTPS only)
);
```

### Security Benefits

| Protection | How It Works |
|------------|-------------|
| **XSS Protection** | HttpOnly flag prevents JavaScript access to the cookie |
| **MITM Protection** | Secure flag ensures cookies are only sent over HTTPS |
| **Path Restriction** | Cookie only sent to `/wp-json/oauth2/v1/` endpoints |
| **Not Visible in Storage** | Refresh token doesn't appear in DevTools Application tab |
| **No Local Storage** | Avoids localStorage/sessionStorage vulnerabilities |

### Refresh Token Rotation

Every time a refresh token is used to obtain a new access token, the plugin issues a **new refresh token** and invalidates the old one.

**Implementation**: [`includes/class-auth-oauth2.php:1036-1053`](../includes/class-auth-oauth2.php#L1036-L1053)

**Benefits:**
- Limits the lifetime of any single refresh token
- Detects token theft (if an old token is reused, it indicates potential compromise)
- Reduces the window of opportunity for attackers

### Token Hashing

Refresh tokens are **never stored in plain text** in the database. Instead, they're hashed using WordPress's secure hashing function.

**Implementation**: [`includes/class-auth-oauth2.php:1379`](../includes/class-auth-oauth2.php#L1379)

```php
$token_hash = wp_auth_oauth2_hash_token($refresh_token, WP_OAUTH2_SECRET);
```

**Benefits:**
- Database breaches don't expose usable tokens
- Even with database access, attackers cannot authenticate
- Tokens are validated by comparing hashes, not plaintext

### Attack Vectors Still Possible

While the implementation follows best practices, no system is completely secure:

| Threat | Risk Level | Mitigation |
|--------|------------|-----------|
| **CSRF on GET requests** | Medium | Use anti-CSRF tokens, avoid state-changing GET requests |
| **Subdomain attacks** | Low | Use separate domains or enable `SameSite` cookie attribute |
| **Server-side breaches** | Medium | Token hashing limits exposure; rotate `WP_OAUTH2_SECRET` regularly |
| **Physical device access** | High | User responsibility; provide token revocation UI |
| **Session hijacking** | Medium | Bind tokens to IP/User-Agent (implement if needed) |

---

## Scope-Based Access Control

The plugin implements **fine-grained permission control** through OAuth2 scopes, ensuring clients can only access the resources they're authorized for.

### Available Scopes

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

### How It Works

1. **User Consent**: During authorization, users explicitly approve the scopes the client is requesting
2. **Scope Storage**: Approved scopes are stored with the access token
3. **Runtime Validation**: Every REST API request validates that the access token has the required scope

**Implementation**: [`includes/class-auth-oauth2.php:1237-1304`](../includes/class-auth-oauth2.php#L1237-L1304)

### Endpoint Scope Mappings

```php
// Examples from the codebase
'GET:/wp/v2/posts'        => ['read'],
'POST:/wp/v2/posts'       => ['write'],
'DELETE:/wp/v2/posts/*'   => ['delete'],
'GET:/wp/v2/media'        => ['read'],
'POST:/wp/v2/media'       => ['upload_files'],
'POST:/wp/v2/users'       => ['manage_users'],
```

### Security Benefits

- **Principle of Least Privilege**: Clients only get the minimum permissions they need
- **User Control**: Users can see and approve what the app can do
- **Defense in Depth**: Even if a token is compromised, damage is limited by scope
- **Audit Trail**: Scope information is logged and can be reviewed

---

## Token Storage and Hashing

### Access Tokens

- **Storage**: WordPress transients (option table or object cache)
- **Lifetime**: 1 hour (configurable via `WP_OAUTH2_ACCESS_TTL`)
- **Format**: Cryptographically random 48-byte strings
- **Revocation**: Can be manually revoked via `/oauth2/v1/revoke` endpoint

**Implementation**: [`includes/class-auth-oauth2.php:899-908`](../includes/class-auth-oauth2.php#L899-L908)

### Refresh Tokens

- **Storage**: Database table `wp_oauth2_refresh_tokens`
- **Lifetime**: 30 days (configurable via `WP_OAUTH2_REFRESH_TTL`)
- **Format**: Cryptographically random 64-byte strings
- **Hashing**: SHA-256 with secret key
- **Rotation**: Automatic rotation on use

**Database Schema**:
```sql
CREATE TABLE wp_oauth2_refresh_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at INT UNSIGNED NOT NULL,
    created_at INT UNSIGNED NOT NULL,
    is_revoked TINYINT(1) DEFAULT 0,
    client_id VARCHAR(255),
    scopes TEXT,
    token_type VARCHAR(50) DEFAULT 'oauth2',
    INDEX idx_token_hash (token_hash),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
);
```

### Secret Key Management

The plugin uses a secret key (`WP_OAUTH2_SECRET`) for token hashing. **Never commit this to version control.**

**Recommended Configuration** (`wp-config.php`):
```php
define('WP_OAUTH2_SECRET', 'your-cryptographically-random-secret-key');
define('WP_OAUTH2_ACCESS_TTL', 3600);      // 1 hour
define('WP_OAUTH2_REFRESH_TTL', 2592000);  // 30 days
```

Generate a secure secret:
```bash
php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
```

---

## Security Best Practices

### For Plugin Users

1. **Always use HTTPS in production** - OAuth2 security relies on TLS
2. **Set a strong `WP_OAUTH2_SECRET`** - Use at least 32 bytes of random data
3. **Restrict redirect URIs** - Only whitelist trusted callback URLs
4. **Monitor token usage** - Check database for suspicious activity
5. **Rotate secrets periodically** - Consider rotating `WP_OAUTH2_SECRET` every 90 days
6. **Implement rate limiting** - Protect token endpoints from brute force attacks
7. **Enable debug logging temporarily** - Only when troubleshooting, never in production

### For Client Developers

1. **Always use PKCE** - Even if client_secret is available
2. **Never log tokens** - Don't console.log() or store tokens in plain text
3. **Store code_verifier securely** - Use sessionStorage, never localStorage
4. **Clear tokens on logout** - Call `/oauth2/v1/logout` endpoint
5. **Handle token expiration gracefully** - Implement automatic refresh logic
6. **Use minimum scopes required** - Don't request unnecessary permissions
7. **Validate redirect_uri** - Prevent open redirect vulnerabilities

### Secure Cookie Configuration

**Cookie Helper**: [`includes/class-oauth2-cookie-config.php`](../includes/class-oauth2-cookie-config.php)

Cookies are configured with:
- `HttpOnly`: Prevents JavaScript access
- `Secure`: Only sent over HTTPS (enforced in production)
- `SameSite=Lax`: CSRF protection (configurable via filter)
- `Path=/wp-json/oauth2/v1/`: Limits cookie scope

---

## Threat Model

### Threats Mitigated

| Threat | Mitigation |
|--------|-----------|
| **Authorization code interception** | PKCE prevents code replay attacks |
| **XSS attacks stealing tokens** | HttpOnly cookies protect refresh tokens |
| **MITM attacks** | Secure flag + HTTPS enforcement |
| **Token theft from database breach** | Token hashing prevents plaintext exposure |
| **Over-privileged access** | Scope-based permissions limit damage |
| **Long-lived token compromise** | Short access token lifetime (1 hour) |
| **Refresh token reuse** | Automatic token rotation |
| **Unauthorized clients** | Client registration and validation |
| **Open redirects** | Strict redirect_uri validation |

### Threats Requiring Additional Measures

| Threat | Recommended Additional Protection |
|--------|----------------------------------|
| **CSRF on state-changing endpoints** | Implement anti-CSRF tokens (planned) |
| **Rate limiting / brute force** | Use a WAF or rate-limiting plugin |
| **Session hijacking** | Implement IP/User-Agent binding |
| **Subdomain cookie theft** | Use separate domains or `SameSite=Strict` |
| **Physical device access** | Implement user-facing token management UI |
| **Malicious client applications** | Implement client approval workflow |

---

## Compliance and Standards

This plugin follows:

- **OAuth 2.0 Authorization Framework (RFC 6749)**: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- **OAuth 2.0 PKCE (RFC 7636)**: [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- **OAuth 2.0 Token Revocation (RFC 7009)**: [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)
- **OAuth 2.0 Security Best Current Practice**: [IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- **OAuth 2.0 for Browser-Based Apps**: [IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)

---

## Security Disclosure

If you discover a security vulnerability, please email the maintainer directly rather than opening a public issue. Responsible disclosure helps protect all users.

**Security Contact**: [Your Email or Security Contact]

---

## Conclusion

**OAuth2 Auth Pro - WP REST API** implements multiple layers of security:

1. ✅ Industry-standard OAuth 2.0 Authorization Code flow
2. ✅ PKCE protection against code interception
3. ✅ HttpOnly, Secure cookies for refresh tokens
4. ✅ Automatic refresh token rotation
5. ✅ Token hashing in database
6. ✅ Scope-based access control
7. ✅ Short-lived access tokens
8. ✅ Redirect URI validation

While no system is perfectly secure, this plugin follows **current best practices** as recommended by the OAuth 2.0 Security Working Group and is suitable for production use when properly configured.

**Remember**: Security is a shared responsibility between the plugin, the server configuration, and the client implementation. Always use HTTPS, rotate secrets regularly, and monitor for suspicious activity.
