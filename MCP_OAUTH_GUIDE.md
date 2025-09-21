# OAuth 2.0 для MCP серверов

## 🤖 Авторизация MCP серверов через OAuth

Теперь наша система может работать как **OAuth 2.0 Authorization Server**, что позволяет MCP серверам и другим приложениям авторизоваться и получать доступ к данным пользователей.

## 🔧 Создание OAuth клиента для MCP сервера

### 1. Регистрация MCP приложения
```bash
# Сначала авторизуйтесь как администратор
curl -X POST "https://auth.yourplatform.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourcompany.com",
    "password": "admin_password"
  }'

# Создайте OAuth клиент для MCP сервера
curl -X POST "https://auth.yourplatform.com/api/v1/oauth/clients" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MCP File Server",
    "description": "MCP server for file operations",
    "redirect_uris": ["http://localhost:8000/oauth/callback"],
    "allowed_scopes": ["profile", "email", "organizations", "users:read", "mcp:connect"],
    "is_confidential": true
  }'

# Response:
{
  "success": true,
  "client": {
    "client_id": "oauth_abc123...",
    "client_secret": "secret_xyz789...",  // Сохраните это!
    "name": "MCP File Server",
    "redirect_uris": ["http://localhost:8000/oauth/callback"],
    "allowed_scopes": ["profile", "email", "organizations", "users:read", "mcp:connect"]
  },
  "warning": "Store client_secret securely. It will not be shown again."
}
```

## 🔑 OAuth Flow для MCP серверов

### 1. Authorization Code Flow

```python
# MCP Server OAuth Client
import requests
import secrets
import hashlib
import base64
import urllib.parse

class MCPOAuthClient:
    def __init__(self, client_id, client_secret, auth_server_base):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_server_base = auth_server_base
        self.redirect_uri = "http://localhost:8000/oauth/callback"
    
    def get_authorization_url(self):
        """Generate authorization URL with PKCE."""
        
        # Generate PKCE parameters
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        
        # Store code_verifier for later use
        self.code_verifier = code_verifier
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'profile email organizations users:read mcp:connect',
            'state': secrets.token_urlsafe(32),
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        
        return f"{self.auth_server_base}/oauth/authorize?{urllib.parse.urlencode(params)}"
    
    def exchange_code(self, code):
        """Exchange authorization code for access token."""
        
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': self.redirect_uri,
            'code_verifier': self.code_verifier
        }
        
        response = requests.post(
            f"{self.auth_server_base}/oauth/token",
            data=data
        )
        
        return response.json()
    
    def get_user_info(self, access_token):
        """Get user information using access token."""
        
        headers = {'Authorization': f'Bearer {access_token}'}
        
        response = requests.get(
            f"{self.auth_server_base}/oauth/userinfo",
            headers=headers
        )
        
        return response.json()
    
    def make_api_call(self, access_token, endpoint):
        """Make authenticated API call."""
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.get(
            f"https://api.yourplatform.com/api/v1{endpoint}",
            headers=headers
        )
        
        return response.json()

# Usage example
oauth_client = MCPOAuthClient(
    client_id="oauth_abc123...",
    client_secret="secret_xyz789...",
    auth_server_base="https://auth.yourplatform.com/api/v1"
)

# Step 1: Get authorization URL
auth_url = oauth_client.get_authorization_url()
print(f"Open this URL to authorize: {auth_url}")

# Step 2: User authorizes and gets redirected with code
# http://localhost:8000/oauth/callback?code=AUTH_CODE&state=STATE

# Step 3: Exchange code for tokens
tokens = oauth_client.exchange_code("AUTH_CODE_FROM_CALLBACK")
print(f"Access token: {tokens['access_token']}")

# Step 4: Use access token to get user info
user_info = oauth_client.get_user_info(tokens['access_token'])
print(f"User: {user_info}")

# Step 5: Make API calls with token
users = oauth_client.make_api_call(tokens['access_token'], '/users/')
organizations = oauth_client.make_api_call(tokens['access_token'], '/organizations/')
```

### 2. MCP Server с OAuth интеграцией

```python
# mcp_server.py
from mcp import ClientSession, InitializationOptions
import asyncio
import json

class AuthenticatedMCPServer:
    def __init__(self, oauth_client):
        self.oauth_client = oauth_client
        self.access_token = None
        self.user_info = None
    
    async def initialize(self):
        """Initialize MCP server with OAuth authentication."""
        
        # Get authorization (в реальном приложении через browser/redirect)
        auth_url = self.oauth_client.get_authorization_url()
        print(f"Please authorize at: {auth_url}")
        
        # Simulate getting authorization code
        code = input("Enter authorization code: ")
        
        # Exchange for tokens
        tokens = self.oauth_client.exchange_code(code)
        self.access_token = tokens['access_token']
        
        # Get user info
        self.user_info = self.oauth_client.get_user_info(self.access_token)
        print(f"Authenticated as: {self.user_info['email']}")
    
    async def handle_list_files(self, organization_id):
        """MCP tool: List files for organization."""
        
        if not self.access_token:
            raise Exception("Not authenticated")
        
        # Check if user has access to organization
        orgs = self.oauth_client.make_api_call(
            self.access_token, 
            '/organizations/'
        )
        
        user_org_ids = [org['organization']['id'] for org in orgs['organizations']]
        
        if organization_id not in user_org_ids:
            raise Exception(f"No access to organization {organization_id}")
        
        # Get users in organization (example API call)
        users = self.oauth_client.make_api_call(
            self.access_token,
            f'/users/?organization_id={organization_id}'
        )
        
        return {
            "files": [
                {
                    "name": f"user_{user['id']}.json",
                    "content": json.dumps(user, indent=2)
                }
                for user in users['users']
            ]
        }
    
    async def handle_get_user_profile(self):
        """MCP tool: Get current user profile."""
        
        if not self.user_info:
            raise Exception("Not authenticated")
        
        return self.user_info

# MCP Server main
async def main():
    # Initialize OAuth client
    oauth_client = MCPOAuthClient(
        client_id="oauth_abc123...",
        client_secret="secret_xyz789...", 
        auth_server_base="https://auth.yourplatform.com/api/v1"
    )
    
    # Initialize authenticated MCP server
    mcp_server = AuthenticatedMCPServer(oauth_client)
    await mcp_server.initialize()
    
    # Now MCP server can make authenticated API calls
    # and provide tools that respect user permissions
    
    print("MCP Server ready with OAuth authentication!")

if __name__ == "__main__":
    asyncio.run(main())
```

## 🔒 Доступные OAuth scopes

```python
AVAILABLE_SCOPES = {
    "profile": "Access to user profile information",
    "email": "Access to user email address", 
    "organizations": "Access to user's organizations",
    "users:read": "Read access to users",
    "users:write": "Write access to users",
    "organizations:read": "Read access to organizations",
    "organizations:write": "Write access to organizations",
    "mcp:connect": "Connect as MCP server",
    "admin": "Administrative access",
}
```

## 🌐 OAuth Discovery

```bash
# OAuth 2.0 Authorization Server Metadata
curl "https://auth.yourplatform.com/api/v1/oauth/.well-known/oauth-authorization-server"

# Response:
{
  "issuer": "https://auth.yourplatform.com/api/v1/oauth",
  "authorization_endpoint": "https://auth.yourplatform.com/api/v1/oauth/authorize",
  "token_endpoint": "https://auth.yourplatform.com/api/v1/oauth/token",
  "userinfo_endpoint": "https://auth.yourplatform.com/api/v1/oauth/userinfo",
  "revocation_endpoint": "https://auth.yourplatform.com/api/v1/oauth/revoke",
  "scopes_supported": ["profile", "email", "organizations", "users:read", "users:write", "mcp:connect", "admin"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "none"]
}
```

## 🔄 Token Management

```python
# Refresh tokens
def refresh_access_token(refresh_token):
    data = {
        'grant_type': 'refresh_token',
        'client_id': client_id,
        'client_secret': client_secret,
        'refresh_token': refresh_token
    }
    
    response = requests.post(f"{auth_server_base}/oauth/token", data=data)
    return response.json()

# Revoke tokens
def revoke_token(access_token):
    data = {
        'token': access_token,
        'client_id': client_id,
        'client_secret': client_secret
    }
    
    response = requests.post(f"{auth_server_base}/oauth/revoke", data=data)
    return response.status_code == 200
```

## 🛡️ Безопасность

### PKCE (обязательный)
- Все public clients должны использовать PKCE
- Code challenge method: S256
- Защита от authorization code interception

### Scopes
- Минимальные права доступа
- Granular permissions
- User consent required

### Token Security
- Short-lived access tokens (1 hour)
- Secure refresh token rotation
- Token revocation support

Теперь **любой MCP сервер** может авторизоваться через OAuth и получать контролируемый доступ к данным пользователей! 🚀
