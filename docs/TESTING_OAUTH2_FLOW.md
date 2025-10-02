# Testing OAuth2 Authorization Code Flow with Refresh Tokens

This guide walks through testing the complete OAuth2 flow including the automatic token refresh on page reload.

## Prerequisites

- WordPress site running at `https://wcg2025-demo.wp.local`
- React app running at `http://localhost:5175`
- OAuth2 plugin activated
- Demo client configured with ID `demo-client`

## Test Environment Configuration

The plugin automatically detects the environment based on:

- **Development**: `localhost`, `*.local`, `*.test` domains, or `WP_DEBUG=true`
- **Staging**: Domains containing "staging", "dev", or "test"
- **Production**: All other domains

### Current Setup
- WordPress: `wcg2025-demo.wp.local` → **Development Environment**
- React App: `localhost:5175` → Cross-origin setup

### Expected Cookie Configuration (Development)
```
SameSite: None (allows cross-origin)
Secure: true (HTTPS required for SameSite=None)
Path: / (broad access for development)
Domain: (empty - current domain only)
HttpOnly: true (always enabled for security)
```

## Testing Steps

### 1. Clear Existing Session
1. Open browser DevTools (F12)
2. Go to Application → Cookies
3. Delete all cookies for both `localhost:5175` and `wcg2025-demo.wp.local`
4. Clear Application → Local Storage

### 2. Start OAuth2 Flow
1. Navigate to `http://localhost:5175/`
2. You should see the login button
3. Click "Login with WordPress OAuth2"

### 3. Authorization & Consent
1. You'll be redirected to `https://wcg2025-demo.wp.local/?oauth2_authorize=1...`
2. If not logged in, WordPress login page appears
3. After login, consent screen shows requested scopes
4. Click "Allow" to grant permissions

### 4. Token Exchange
1. Browser redirects back to `http://localhost:5175/callback?code=...`
2. React app exchanges the authorization code for tokens
3. Check browser console for success messages

### 5. Verify Access Token
1. In DevTools Console, check the auth state:
   ```javascript
   // Access token should be in memory (not in cookies)
   console.log('Auth context loaded')
   ```
2. User info should be displayed in the app

### 6. Verify Refresh Token Cookie

**In DevTools → Application → Cookies → `wcg2025-demo.wp.local`:**

You should see a cookie named `wp_oauth2_refresh_token` with:
- ✅ HttpOnly: Yes
- ✅ Secure: Yes
- ✅ SameSite: None
- ✅ Path: `/` (development) or `/wp-json/oauth2/v1/` (production)
- ✅ Expires: ~30 days from now

**IMPORTANT**: Due to SameSite=None, the cookie requires HTTPS. If you see the cookie but it's not being sent:
- Verify WordPress is using HTTPS (`https://wcg2025-demo.wp.local`)
- Check that your `.local` domain has a valid SSL certificate

### 7. Test Automatic Token Refresh (THE KEY TEST!)

This is the critical test to verify the refresh token flow works:

1. **With the user logged in**, refresh the page (`Cmd+R` or `F5`)
2. The app should:
   - Detect no access token in memory
   - Automatically call `/wp-json/oauth2/v1/refresh`
   - The refresh token cookie is sent automatically by the browser
   - Receive a new access token
   - Store it in memory
   - Display user info again

**Verify in Network Tab (DevTools → Network):**
1. Filter by "refresh"
2. Find the `POST /wp-json/oauth2/v1/refresh` request
3. Check Request Headers:
   ```
   Cookie: wp_oauth2_refresh_token=...
   ```
4. Check Response:
   ```json
   {
     "success": true,
     "data": {
       "access_token": "...",
       "token_type": "Bearer",
       "expires_in": 3600,
       "scope": "read write upload_files"
     }
   }
   ```

### 8. Test Authenticated API Calls

With a valid access token, test making API calls:

1. Use the API tester in the React app
2. Try endpoints like:
   - `GET /wp-json/wp/v2/posts`
   - `GET /wp-json/wp/v2/media`
   - `GET /wp-json/oauth2/v1/userinfo`

**In DevTools → Network:**
1. Find the API request
2. Check Request Headers include:
   ```
   Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
   ```
3. Verify response is successful (200 OK)

## Troubleshooting

### Cookie Not Being Set
**Symptom**: No `wp_oauth2_refresh_token` cookie appears

**Possible Causes**:
1. WordPress not using HTTPS (required for SameSite=None)
2. Cookie path mismatch
3. Browser blocking third-party cookies

**Solutions**:
- Verify WordPress URL starts with `https://`
- Check Admin → WP REST Auth OAuth2 → Cookie Settings tab
- Ensure "SameSite" is set to "None" for development

### Cookie Not Being Sent on Refresh
**Symptom**: Cookie exists but `/refresh` endpoint returns "missing_refresh_token"

**Possible Causes**:
1. Cookie path doesn't match request path
2. SameSite attribute preventing cross-origin sending
3. Domain mismatch

**Solutions**:
- Check cookie path in DevTools (should be `/` for development)
- Verify SameSite is "None"
- Ensure Secure flag is enabled
- Check CORS settings include `http://localhost:5175`

### Token Refresh Fails
**Symptom**: `/refresh` endpoint returns error

**Check**:
1. Cookie is present and being sent
2. Refresh token hasn't expired (30 days default)
3. WordPress error logs: `/wp-content/debug.log`
4. Browser console for detailed error messages

### CORS Errors
**Symptom**: Browser blocks requests with CORS error

**Solution**:
1. Go to WordPress Admin → Settings → WP REST Auth OAuth2 → General Settings
2. Add to CORS Allowed Origins:
   ```
   http://localhost:5175
   ```
3. Save changes

## Verifying Cookie Configuration

You can check the active cookie configuration:

1. Go to WordPress Admin
2. Navigate to Settings → WP REST Auth OAuth2
3. Click "Cookie Settings" tab
4. Review:
   - Current Environment (should show "development")
   - Active Cookie Configuration table

## Expected Behavior Summary

| Event | Expected Behavior |
|-------|-------------------|
| Initial login | Access token in memory, refresh token in HttpOnly cookie |
| Page refresh | Auto-calls `/refresh`, gets new access token |
| Cookie expires | User must re-authenticate |
| Logout | Cookie deleted, access token cleared |
| API calls | Include `Authorization: Bearer <token>` header |

## Success Criteria

✅ User can log in via OAuth2 flow
✅ Access token received and stored in memory
✅ Refresh token cookie set with correct attributes
✅ Page refresh automatically retrieves new access token
✅ No manual re-authentication needed until cookie expires
✅ Authenticated API calls work
✅ Cross-origin cookies work in development

## Debug Logging

Enable debug logging to troubleshoot:

1. Go to WordPress Admin → Settings → WP REST Auth OAuth2 → General Settings
2. Enable "Debug Logging"
3. Check `/wp-content/debug.log` for detailed OAuth2 flow information

## Testing with cURL

For backend testing without the React app:

```bash
# 1. Get authorization code (requires browser/manual step)

# 2. Exchange code for tokens
curl -X POST 'https://wcg2025-demo.wp.local/wp-json/oauth2/v1/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=YOUR_AUTH_CODE' \
  -d 'redirect_uri=http://localhost:5175/callback' \
  -d 'client_id=demo-client' \
  -d 'code_verifier=YOUR_PKCE_VERIFIER' \
  -c cookies.txt \
  -k

# 3. Test refresh token
curl -X POST 'https://wcg2025-demo.wp.local/wp-json/oauth2/v1/refresh' \
  -b cookies.txt \
  -c cookies.txt \
  -k

# 4. Test authenticated request
curl 'https://wcg2025-demo.wp.local/wp-json/oauth2/v1/userinfo' \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' \
  -k
```

## Notes

- The refresh token cookie is **HttpOnly** - JavaScript cannot access it (this is a security feature)
- Access tokens are **short-lived** (1 hour default) for security
- Refresh tokens are **long-lived** (30 days default) but can be revoked
- In production, use proper SSL certificates, not self-signed
