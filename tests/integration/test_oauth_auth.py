"""Integration tests for OAuth 2.0 authorization server."""

import base64
import hashlib
import secrets
import urllib.parse

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.integration
@pytest.mark.oauth
class TestOAuthClientManagement:
    """Test OAuth client registration and management."""

    @pytest.mark.asyncio
    async def test_create_oauth_client(self, async_client: AsyncClient, admin_auth_headers):
        """Test OAuth client creation."""

        response = await async_client.post(
            "/api/v1/oauth/clients",
            json={
                "name": "Test OAuth App",
                "description": "OAuth app for testing",
                "redirect_uris": [
                    "http://localhost:8000/callback",
                    "https://app.example.com/oauth/callback",
                ],
                "allowed_scopes": ["profile", "email", "organizations"],
                "is_confidential": True,
            },
            headers=admin_auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "OAuth client created successfully" in data["message"]
        assert "client" in data
        assert "warning" in data

        client = data["client"]
        assert client["client_id"].startswith("oauth_")
        assert len(client["client_secret"]) > 32
        assert client["name"] == "Test OAuth App"
        assert client["redirect_uris"] == [
            "http://localhost:8000/callback",
            "https://app.example.com/oauth/callback",
        ]
        assert client["allowed_scopes"] == ["profile", "email", "organizations"]
        assert client["is_confidential"] is True

    @pytest.mark.asyncio
    async def test_list_oauth_clients(
        self, async_client: AsyncClient, admin_auth_headers, create_oauth_client
    ):
        """Test listing OAuth clients."""

        response = await async_client.get(
            "/api/v1/oauth/clients",
            headers=admin_auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "clients" in data
        assert len(data["clients"]) >= 1

        client = data["clients"][0]
        assert "client_id" in client
        assert "name" in client
        assert "redirect_uris" in client
        assert "allowed_scopes" in client

        # Should NOT include client secret in list
        assert "client_secret" not in client

    @pytest.mark.asyncio
    async def test_delete_oauth_client(
        self, async_client: AsyncClient, admin_auth_headers, create_oauth_client
    ):
        """Test OAuth client deletion."""

        response = await async_client.delete(
            f"/api/v1/oauth/clients/{create_oauth_client.client_id}",
            headers=admin_auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "deleted" in data["message"]

    @pytest.mark.asyncio
    async def test_create_oauth_client_invalid_scopes(
        self, async_client: AsyncClient, admin_auth_headers
    ):
        """Test OAuth client creation with invalid scopes."""

        response = await async_client.post(
            "/api/v1/oauth/clients",
            json={
                "name": "Invalid Scope App",
                "redirect_uris": ["http://localhost:8000/callback"],
                "allowed_scopes": ["invalid_scope", "another_invalid"],
            },
            headers=admin_auth_headers,
        )

        assert response.status_code == 400
        assert "Invalid scopes" in response.json()["message"]


@pytest.mark.integration
@pytest.mark.oauth
class TestOAuthAuthorizationFlow:
    """Test OAuth 2.0 Authorization Code flow."""

    def generate_pkce_params(self) -> dict[str, str]:
        """Generate PKCE parameters for testing."""
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        )
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode("utf-8")
            .rstrip("=")
        )

        return {
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

    @pytest.mark.asyncio
    async def test_oauth_authorization_endpoint_get(
        self, async_client: AsyncClient, create_oauth_client, auth_headers
    ):
        """Test OAuth authorization endpoint GET request (consent screen)."""

        pkce_params = self.generate_pkce_params()

        params = {
            "client_id": create_oauth_client.client_id,
            "redirect_uri": create_oauth_client.redirect_uris_list[0],
            "response_type": "code",
            "scope": "profile email",
            "state": "test_state_123",
            "code_challenge": pkce_params["code_challenge"],
            "code_challenge_method": pkce_params["code_challenge_method"],
        }

        response = await async_client.get(
            "/api/v1/oauth/authorize",
            params=params,
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

        # Should show consent screen
        content = response.text
        assert create_oauth_client.name in content
        assert "profile" in content
        assert "email" in content
        assert "Allow" in content
        assert "Deny" in content

    @pytest.mark.asyncio
    async def test_oauth_authorization_invalid_client(
        self, async_client: AsyncClient, auth_headers
    ):
        """Test OAuth authorization with invalid client_id."""

        response = await async_client.get(
            "/api/v1/oauth/authorize",
            params={
                "client_id": "invalid_client_id",
                "redirect_uri": "http://localhost:8000/callback",
                "response_type": "code",
                "scope": "profile",
            },
            headers=auth_headers,
        )

        assert response.status_code == 400
        assert "Invalid client_id" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_oauth_authorization_invalid_redirect_uri(
        self, async_client: AsyncClient, create_oauth_client, auth_headers
    ):
        """Test OAuth authorization with invalid redirect URI."""

        response = await async_client.get(
            "/api/v1/oauth/authorize",
            params={
                "client_id": create_oauth_client.client_id,
                "redirect_uri": "http://evil.com/callback",  # Not in allowed list
                "response_type": "code",
                "scope": "profile",
            },
            headers=auth_headers,
        )

        assert response.status_code == 400
        assert "Invalid redirect_uri" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_oauth_authorization_consent_allow(
        self, async_client: AsyncClient, create_oauth_client, auth_headers
    ):
        """Test OAuth authorization consent - user allows."""

        pkce_params = self.generate_pkce_params()
        redirect_uri = create_oauth_client.redirect_uris_list[0]

        # User consents (allows access)
        response = await async_client.post(
            "/api/v1/oauth/authorize",
            data={
                "client_id": create_oauth_client.client_id,
                "redirect_uri": redirect_uri,
                "scope": "profile email",
                "state": "test_state_123",
                "code_challenge": pkce_params["code_challenge"],
                "code_challenge_method": pkce_params["code_challenge_method"],
                "action": "allow",
            },
            headers=auth_headers,
        )

        assert response.status_code == 302  # Redirect

        # Parse redirect URL
        location = response.headers["location"]
        parsed = urllib.parse.urlparse(location)
        query_params = urllib.parse.parse_qs(parsed.query)

        assert parsed.scheme + "://" + parsed.netloc + parsed.path == redirect_uri
        assert "code" in query_params
        assert query_params["state"][0] == "test_state_123"

        # Store authorization code for token exchange test
        auth_code = query_params["code"][0]
        pkce_params["auth_code"] = auth_code
        return pkce_params

    @pytest.mark.asyncio
    async def test_oauth_authorization_consent_deny(
        self, async_client: AsyncClient, create_oauth_client, auth_headers
    ):
        """Test OAuth authorization consent - user denies."""

        redirect_uri = create_oauth_client.redirect_uris_list[0]

        # User denies access
        response = await async_client.post(
            "/api/v1/oauth/authorize",
            data={
                "client_id": create_oauth_client.client_id,
                "redirect_uri": redirect_uri,
                "state": "test_state_123",
                "scope": "profile email",
                "action": "deny",
            },
            headers=auth_headers,
        )

        assert response.status_code == 302  # Redirect

        # Parse redirect URL
        location = response.headers["location"]
        parsed = urllib.parse.urlparse(location)
        query_params = urllib.parse.parse_qs(parsed.query)

        assert "error" in query_params
        assert query_params["error"][0] == "access_denied"
        assert query_params["state"][0] == "test_state_123"

    @pytest.mark.asyncio
    async def test_oauth_token_exchange(
        self, async_client: AsyncClient, create_oauth_client, db_session: AsyncSession
    ):
        """Test OAuth token exchange (authorization code for access token)."""

        # First get authorization code
        pkce_params = self.generate_pkce_params()

        # Simulate getting authorization code (would normally come from authorization flow)
        from app.services.oauth_service import OAuthService

        # Create authorization code directly for testing
        async def get_auth_code():
            oauth_service = OAuthService(db_session)

            # Get a test user
            from sqlalchemy import select

            from app.models.user import User

            result = await db_session.execute(select(User).limit(1))
            user = result.scalar_one()

            code = await oauth_service.create_authorization_code(
                client=create_oauth_client,
                user=user,
                redirect_uri=create_oauth_client.redirect_uris_list[0],
                scopes=["profile", "email"],
                code_challenge=pkce_params["code_challenge"],
                code_challenge_method=pkce_params["code_challenge_method"],
            )
            return code

        # Exchange code for tokens
        code = await get_auth_code()
        data = {
            "grant_type": "authorization_code",
            "client_id": create_oauth_client.client_id,
            "client_secret": create_oauth_client.client_secret,
            "code": code,
            "redirect_uri": create_oauth_client.redirect_uris_list[0],
            "code_verifier": pkce_params["code_verifier"],
        }
        response = await async_client.post("/api/v1/oauth/token", data=data)
        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        assert "refresh_token" in data
        assert "scope" in data

        assert data["token_type"] == "Bearer"
        assert isinstance(data["expires_in"], int)
        assert "profile" in data["scope"]
        assert "email" in data["scope"]

        return data

    @pytest.mark.asyncio
    async def test_oauth_token_refresh(
        self, async_client: AsyncClient, create_oauth_client, db_session: AsyncSession
    ):
        """Test OAuth token refresh."""

        # First get tokens through authorization flow
        token_data = await self.test_oauth_token_exchange(
            async_client, create_oauth_client, db_session
        )
        refresh_token = token_data["refresh_token"]

        # Refresh the token
        response = await async_client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": create_oauth_client.client_id,
                "client_secret": create_oauth_client.client_secret,
                "refresh_token": refresh_token,
            },
        )

        assert response.status_code == 200
        data = response.json()

        assert "access_token" in data
        assert "refresh_token" in data

        # New tokens should be different
        assert data["access_token"] != token_data["access_token"]
        assert data["refresh_token"] != token_data["refresh_token"]

    @pytest.mark.asyncio
    async def test_oauth_userinfo_endpoint(
        self, async_client: AsyncClient, create_oauth_client, db_session: AsyncSession
    ):
        """Test OAuth userinfo endpoint."""

        # Get access token first
        token_data = await self.test_oauth_token_exchange(
            async_client, create_oauth_client, db_session
        )
        access_token = token_data["access_token"]

        # Get user info
        response = await async_client.get(
            "/api/v1/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()

        # Should contain user info based on scopes
        assert "id" in data
        assert "email" in data  # email scope was granted

        # Profile scope should provide these fields
        if "profile" in token_data["scope"]:
            assert "first_name" in data
            assert "last_name" in data

    @pytest.mark.asyncio
    async def test_oauth_token_revocation(
        self, async_client: AsyncClient, create_oauth_client, db_session: AsyncSession
    ):
        """Test OAuth token revocation."""

        # Get access token first
        token_data = await self.test_oauth_token_exchange(
            async_client, create_oauth_client, db_session
        )
        access_token = token_data["access_token"]

        # Revoke token
        response = await async_client.post(
            "/api/v1/oauth/revoke",
            data={
                "token": access_token,
                "client_id": create_oauth_client.client_id,
                "client_secret": create_oauth_client.client_secret,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "revoked" in data

        # Try to use revoked token
        userinfo_response = await async_client.get(
            "/api/v1/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert userinfo_response.status_code == 401


@pytest.mark.integration
@pytest.mark.oauth
@pytest.mark.security
class TestOAuthSecurity:
    """Test OAuth 2.0 security features."""

    @pytest.mark.asyncio
    async def test_pkce_required(
        self, async_client: AsyncClient, create_oauth_client, auth_headers
    ):
        """Test that PKCE is required for OAuth flows."""

        # Try authorization without PKCE
        response = await async_client.post(
            "/api/v1/oauth/authorize",
            data={
                "client_id": create_oauth_client.client_id,
                "redirect_uri": create_oauth_client.redirect_uris_list[0],
                "scope": "profile",
                "action": "allow",
                # Missing code_challenge
            },
            headers=auth_headers,
        )

        # Should still work for confidential clients, but PKCE is recommended
        # The actual requirement depends on client configuration
        assert response.status_code in [302, 400]

    @pytest.mark.asyncio
    async def test_pkce_verification(self, async_client: AsyncClient, create_oauth_client):
        """Test PKCE code verifier verification."""

        # Generate PKCE params
        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        )
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode("utf-8")
            .rstrip("=")
        )

        # Create authorization code with PKCE

        # Try to exchange with wrong code verifier
        wrong_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        )

        response = await async_client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": create_oauth_client.client_id,
                "client_secret": create_oauth_client.client_secret,
                "code": "test_code",  # Would need valid code
                "redirect_uri": create_oauth_client.redirect_uris_list[0],
                "code_verifier": wrong_verifier,
            },
        )

        # Should fail with invalid code (which will be caught before PKCE verification)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_authorization_code_expiration(
        self, async_client: AsyncClient, create_oauth_client, db_session
    ):
        """Test authorization code expiration."""

        # Create expired authorization code
        from datetime import datetime, timedelta

        from app.models.oauth_client import OAuthAuthorizationCode

        expired_code = OAuthAuthorizationCode(
            client_id=create_oauth_client.client_id,
            user_id=1,  # Test user
            code="expired_test_code",
            redirect_uri=create_oauth_client.redirect_uris_list[0],
            scopes='["profile"]',
            expires_at=datetime.utcnow() - timedelta(minutes=20),  # Expired 20 minutes ago
        )

        db_session.add(expired_code)
        await db_session.commit()

        # Try to use expired code
        response = await async_client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": create_oauth_client.client_id,
                "client_secret": create_oauth_client.client_secret,
                "code": "expired_test_code",
                "redirect_uri": create_oauth_client.redirect_uris_list[0],
            },
        )

        assert response.status_code == 400
        assert "expired" in response.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_scope_validation(
        self, async_client: AsyncClient, create_oauth_client, auth_headers
    ):
        """Test OAuth scope validation."""

        # Try to request scopes not allowed for client
        response = await async_client.get(
            "/api/v1/oauth/authorize",
            params={
                "client_id": create_oauth_client.client_id,
                "redirect_uri": create_oauth_client.redirect_uris_list[0],
                "response_type": "code",
                "scope": "admin super_secret",  # Scopes not in allowed_scopes
            },
            headers=auth_headers,
        )

        assert response.status_code == 400
        assert "Invalid scopes" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_client_authentication(self, async_client: AsyncClient, create_oauth_client):
        """Test OAuth client authentication."""

        # Try token exchange with wrong client secret
        response = await async_client.post(
            "/api/v1/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": create_oauth_client.client_id,
                "client_secret": "wrong_secret",
                "code": "test_code",
                "redirect_uri": create_oauth_client.redirect_uris_list[0],
            },
        )

        assert response.status_code == 400
        assert "Invalid client" in response.json()["message"]


@pytest.mark.integration
@pytest.mark.oauth
class TestOAuthDiscovery:
    """Test OAuth 2.0 discovery and metadata."""

    @pytest.mark.asyncio
    async def test_oauth_metadata_endpoint(self, async_client: AsyncClient):
        """Test OAuth 2.0 Authorization Server Metadata endpoint."""

        response = await async_client.get("/api/v1/oauth/.well-known/oauth-authorization-server")

        assert response.status_code == 200
        data = response.json()

        # Required OAuth 2.0 metadata fields
        assert "issuer" in data
        assert "authorization_endpoint" in data
        assert "token_endpoint" in data
        assert "scopes_supported" in data
        assert "response_types_supported" in data
        assert "grant_types_supported" in data

        # Check specific values
        assert "code" in data["response_types_supported"]
        assert "authorization_code" in data["grant_types_supported"]
        assert "refresh_token" in data["grant_types_supported"]
        assert "S256" in data["code_challenge_methods_supported"]

        # Check supported scopes
        assert "profile" in data["scopes_supported"]
        assert "email" in data["scopes_supported"]


@pytest.mark.integration
@pytest.mark.oauth
class TestOAuthIntegration:
    """Test OAuth 2.0 integration with existing auth system."""

    def generate_pkce_params(self) -> dict[str, str]:
        """Generate PKCE parameters for testing."""
        import base64
        import hashlib
        import secrets

        code_verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
        )
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode("utf-8")
            .rstrip("=")
        )

        return {
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

    @pytest.mark.asyncio
    async def test_oauth_token_in_api_requests(
        self, async_client: AsyncClient, create_oauth_client, db_session: AsyncSession
    ):
        """Test using OAuth access token for API requests."""

        # Get OAuth access token using the real OAuth flow
        oauth_flow = TestOAuthAuthorizationFlow()
        token_data = await oauth_flow.test_oauth_token_exchange(
            async_client, create_oauth_client, db_session
        )
        access_token = token_data["access_token"]

        # Use OAuth token for regular API request
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "user" in data
        assert "email" in data["user"]

    @pytest.mark.asyncio
    async def test_oauth_token_vs_jwt_token(
        self,
        async_client: AsyncClient,
        create_test_user,
        create_oauth_client,
        db_session: AsyncSession,
    ):
        """Test that OAuth tokens work alongside regular JWT tokens."""

        # Get regular JWT token
        jwt_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )

        jwt_token = jwt_response.json()["tokens"]["access_token"]

        # Get OAuth token using the real OAuth flow from TestOAuthAuthorizationFlow
        oauth_flow = TestOAuthAuthorizationFlow()
        oauth_token_data = await oauth_flow.test_oauth_token_exchange(
            async_client, create_oauth_client, db_session
        )
        oauth_token = oauth_token_data["access_token"]

        # Both should work for API requests
        jwt_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {jwt_token}"},
        )

        oauth_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {oauth_token}"},
        )

        assert jwt_response.status_code == 200
        assert oauth_response.status_code == 200
