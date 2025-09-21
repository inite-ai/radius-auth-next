# Client Authentication Examples

## 🌐 Browser Clients (React/Vue/Angular)

### Login
```javascript
// Browser login - automatically detects client type
const response = await fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCsrfToken(), // From cookie
  },
  credentials: 'include', // Important for cookies
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123',
    remember_me: false
  })
});

const data = await response.json();
// Response: { success: true, user: {...}, tokens: null }
// Session cookie automatically set by server
```

### Making authenticated requests
```javascript
// No need to handle tokens manually - cookies handle it
const response = await fetch('/api/v1/users/', {
  headers: {
    'X-CSRF-Token': getCsrfToken(),
  },
  credentials: 'include'
});
```

### Logout
```javascript
const response = await fetch('/api/v1/auth/logout', {
  method: 'POST',
  credentials: 'include'
});
// Session cookie automatically cleared
```

---

## 📱 Mobile Clients (iOS/Android/Flutter)

### Login
```dart
// Flutter example
final response = await http.post(
  Uri.parse('$baseUrl/api/v1/auth/mobile/login'),
  headers: {
    'Content-Type': 'application/json',
    'User-Agent': 'MyApp/1.0 (Flutter)',
  },
  body: jsonEncode({
    'email': 'user@example.com',
    'password': 'password123',
    'remember_me': true,
  }),
);

final data = jsonDecode(response.body);
// Response: { success: true, user: {...}, tokens: {...} }

// Store tokens securely
await secureStorage.write(key: 'access_token', value: data['tokens']['access_token']);
await secureStorage.write(key: 'refresh_token', value: data['tokens']['refresh_token']);
```

### Making authenticated requests
```dart
final accessToken = await secureStorage.read(key: 'access_token');

final response = await http.get(
  Uri.parse('$baseUrl/api/v1/users/'),
  headers: {
    'Authorization': 'Bearer $accessToken',
    'Content-Type': 'application/json',
  },
);
```

### Token refresh
```dart
final refreshToken = await secureStorage.read(key: 'refresh_token');

final response = await http.post(
  Uri.parse('$baseUrl/api/v1/auth/refresh'),
  headers: {'Content-Type': 'application/json'},
  body: jsonEncode({
    'refresh_token': refreshToken,
  }),
);

final data = jsonDecode(response.body);
// Store new tokens
await secureStorage.write(key: 'access_token', value: data['tokens']['access_token']);
await secureStorage.write(key: 'refresh_token', value: data['tokens']['refresh_token']);
```

---

## 🤖 API Clients (Machine-to-Machine)

### Create API Key
```bash
# First login as user to get JWT
curl -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "password123"
  }'

# Create API key
curl -X POST "$BASE_URL/api/v1/auth/api-key/create" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Integration Script",
    "scopes": ["users:read", "organizations:read"],
    "expires_days": 365
  }'

# Response: { api_key: "pauth_xxx...", warning: "Store securely" }
```

### Using API Key
```bash
# Use API key for all requests
curl -X GET "$BASE_URL/api/v1/users/" \
  -H "X-API-Key: pauth_xxx..." \
  -H "Content-Type: application/json"
```

### Python example
```python
import requests

class PlatformAuthAPI:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }

    def get_users(self, organization_id=None):
        params = {}
        if organization_id:
            params['organization_id'] = organization_id

        response = requests.get(
            f'{self.base_url}/api/v1/users/',
            headers=self.headers,
            params=params
        )
        return response.json()

# Usage
api = PlatformAuthAPI('https://api.example.com', 'pauth_xxx...')
users = api.get_users(organization_id=123)
```

---

## 🔐 OAuth/Social Login (Coming Soon)

### Google OAuth
```javascript
// Frontend: Redirect to OAuth
window.location.href = '/api/v1/auth/oauth/google';

// Backend callback handles:
// 1. Exchange code for tokens
// 2. Get user info from Google
// 3. Link/create oauth_identity record
// 4. Return session/tokens based on client type
```

---

## 🛡️ Security Features in Action

### CSRF Protection (Browsers Only)
```javascript
// CSRF token automatically set in cookie: csrf_token
// Include in header for state-changing operations
fetch('/api/v1/users/', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': document.cookie.match(/csrf_token=([^;]+)/)[1],
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify(userData)
});
```

### Session Management
```javascript
// Get all active sessions
const sessions = await fetch('/api/v1/sessions/', {
  credentials: 'include'
}).then(r => r.json());

// Revoke specific session
await fetch(`/api/v1/sessions/${sessionId}`, {
  method: 'DELETE',
  credentials: 'include'
});

// Logout from all other sessions
await fetch('/api/v1/sessions/other', {
  method: 'DELETE',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    current_session_id: 'current_session_xxx'
  })
});
```

### Rate Limiting
```bash
# Rate limits applied automatically:
# - IP-based: 60 req/min
# - User-based: 120 req/min
# - API key-based: 300 req/min

# Rate limit headers in response:
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 1640995200
```

---

## 🔧 Integration Patterns

### Multi-Organization Context
```javascript
// Switch organization context
const orgUsers = await fetch('/api/v1/users/?organization_id=123', {
  headers: { 'Authorization': `Bearer ${token}` }
});

// Get user's organizations
const orgs = await fetch('/api/v1/organizations/', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

### Error Handling
```javascript
async function apiCall(url, options) {
  const response = await fetch(url, options);

  if (response.status === 401) {
    // Token expired - try refresh
    await refreshToken();
    // Retry request
  } else if (response.status === 403) {
    // Insufficient permissions
    showErrorMessage('Access denied');
  } else if (response.status === 429) {
    // Rate limited
    const retryAfter = response.headers.get('Retry-After');
    await sleep(retryAfter * 1000);
    // Retry request
  }

  return response.json();
}
```

This implementation provides **complete separation** of authentication strategies while maintaining a **unified API** that automatically detects and handles different client types appropriately.
