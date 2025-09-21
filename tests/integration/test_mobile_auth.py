"""Integration tests for mobile authentication (JWT tokens)."""

import pytest
from httpx import AsyncClient


@pytest.mark.integration
@pytest.mark.auth
class TestMobileAuthentication:
    """Test mobile authentication with JWT access/refresh tokens."""
    
    @pytest.mark.asyncio
    async def test_mobile_login_success(self, async_client: AsyncClient, create_test_user):
        """Test successful mobile login with JWT tokens."""
        
        response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
                "remember_me": False,
            },
            headers={
                "User-Agent": "TestApp/1.0 (iOS; Version 14.0)",
                "Accept": "application/json",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Mobile client should receive tokens in response body
        assert data["success"] is True
        assert "Mobile login successful" in data["message"]
        assert "tokens" in data
        assert "user" in data
        assert "device_info" in data
        
        tokens = data["tokens"]
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "token_type" in tokens
        assert "expires_in" in tokens
        assert tokens["token_type"] == "Bearer"
        assert isinstance(tokens["expires_in"], int)
        
        # Should NOT set cookies for mobile
        assert len(response.cookies) == 0
    
    @pytest.mark.asyncio
    async def test_universal_login_mobile_detection(self, async_client: AsyncClient, create_test_user):
        """Test universal login endpoint with mobile User-Agent detection."""
        
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "MyApp/1.0 (Android; Version 11.0)",
                "Accept": "application/json",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should detect as mobile and return tokens
        assert "mobile client" in data["message"]
        assert data["tokens"] is not None
        assert len(response.cookies) == 0
    
    @pytest.mark.asyncio
    async def test_mobile_token_authentication(self, async_client: AsyncClient, create_test_user):
        """Test authentication using JWT access token."""
        
        # Login to get tokens
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )
        
        response_data = login_response.json()
        
        tokens = response_data["tokens"]
        access_token = tokens["access_token"]
        
        # Use access token for authenticated request
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == create_test_user.email
    
    @pytest.mark.asyncio
    async def test_mobile_token_refresh(self, async_client: AsyncClient, create_test_user):
        """Test JWT token refresh flow."""
        
        # Login to get tokens
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )
        
        assert login_response.status_code == 200, f"Login failed: {login_response.text}"
        tokens = login_response.json()["tokens"]
        refresh_token = tokens["refresh_token"]
        
        # Refresh tokens
        refresh_response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token, "organization_id": None},
        )
        
        assert refresh_response.status_code == 200, f"Refresh failed: {refresh_response.text}"
        data = refresh_response.json()
        
        assert data["success"] is True
        assert "tokens" in data
        
        new_tokens = data["tokens"]
        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        
        # New tokens should be different from old ones
        assert new_tokens["access_token"] != tokens["access_token"]
        assert new_tokens["refresh_token"] != tokens["refresh_token"]
        
        # Old refresh token should be invalidated (rotation)
        old_refresh_response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token, "organization_id": None},
        )
        
        # Old refresh token should be invalidated (rotation) - could be 401 or 422
        assert old_refresh_response.status_code in [401, 422]
    
    @pytest.mark.asyncio
    async def test_mobile_logout(self, async_client: AsyncClient, create_test_user):
        """Test mobile logout with token revocation."""
        
        # Login to get tokens
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )
        
        tokens = login_response.json()["tokens"]
        access_token = tokens["access_token"]
        
        # Logout
        logout_response = await async_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        assert logout_response.status_code == 200
        data = logout_response.json()
        assert data["success"] is True
        
        # Token should be revoked
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        assert profile_response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_mobile_invalid_token(self, async_client: AsyncClient):
        """Test request with invalid JWT token."""
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": "Bearer invalid_jwt_token"},
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_mobile_expired_token(self, async_client: AsyncClient, create_test_user, db_session):
        """Test request with expired JWT token."""
        
        # Create manually expired token
        from app.services.jwt_service import JWTService
        from datetime import datetime, timedelta
        import jwt
        
        jwt_service = JWTService()
        
        # Create token that expired 1 hour ago
        payload = {
            "sub": str(create_test_user.id),
            "email": create_test_user.email,
            "exp": datetime.utcnow() - timedelta(hours=1),
            "iat": datetime.utcnow() - timedelta(hours=2),
            "type": "access",
        }
        
        # Use jwt.encode directly to create expired token
        expired_token = jwt.encode(
            payload,
            jwt_service._get_private_key(),
            algorithm=jwt_service.algorithm,
        )
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        
        assert response.status_code == 401


@pytest.mark.integration
@pytest.mark.auth
class TestMobileDeviceDetection:
    """Test mobile device detection and session metadata."""
    
    @pytest.mark.asyncio
    async def test_ios_detection(self, async_client: AsyncClient, create_test_user):
        """Test iOS device detection."""
        
        response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "MyApp/1.0 CFNetwork/1240.0.4 Darwin/20.6.0",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        device_info = data["device_info"]
        assert device_info["device_type"] == "mobile"
    
    @pytest.mark.asyncio
    async def test_android_detection(self, async_client: AsyncClient, create_test_user):
        """Test Android device detection."""
        
        response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "MyApp/1.0 (Linux; Android 11; SM-G991B)",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        device_info = data["device_info"]
        assert device_info["device_type"] == "mobile"
    
    @pytest.mark.asyncio
    async def test_flutter_detection(self, async_client: AsyncClient, create_test_user):
        """Test Flutter app detection."""
        
        response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Dart/2.14 (dart:io) Flutter/2.5.1",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        device_info = data["device_info"]
        assert device_info["device_type"] == "mobile"


@pytest.mark.integration
@pytest.mark.auth
@pytest.mark.security
class TestMobileTokenSecurity:
    """Test mobile token security features."""
    
    @pytest.mark.asyncio
    async def test_token_refresh_rotation(self, async_client: AsyncClient, create_test_user, db_session):
        """Test refresh token rotation security."""
        
        # Login to get initial tokens
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )
        
        tokens = login_response.json()["tokens"]
        refresh_token_1 = tokens["refresh_token"]
        
        # First refresh
        refresh_response_1 = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token_1},
        )
        
        assert refresh_response_1.status_code == 200
        new_tokens_1 = refresh_response_1.json()["tokens"]
        refresh_token_2 = new_tokens_1["refresh_token"]
        
        # Second refresh with new token
        refresh_response_2 = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token_2},
        )
        
        assert refresh_response_2.status_code == 200
        
        # Try to reuse first refresh token (should fail)
        reuse_response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token_1},
        )
        
        assert reuse_response.status_code == 401
        
        # Try to reuse second refresh token (should also fail due to rotation)
        reuse_response_2 = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token_2},
        )
        
        assert reuse_response_2.status_code == 401
    
    @pytest.mark.asyncio
    async def test_refresh_token_reuse_detection(self, async_client: AsyncClient, create_test_user):
        """Test refresh token reuse detection and session banning."""
        
        # Login to get tokens
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )
        
        tokens = login_response.json()["tokens"]
        refresh_token = tokens["refresh_token"]
        access_token = tokens["access_token"]
        
        # Use refresh token once
        await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        
        # Try to reuse same refresh token (potential attack)
        reuse_response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        
        assert reuse_response.status_code == 401
        
        # Original access token should also be invalidated
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        assert profile_response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_jwt_tampering_detection(self, async_client: AsyncClient, create_test_user):
        """Test JWT tampering detection."""
        
        # Login to get valid token
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )
        
        tokens = login_response.json()["tokens"]
        access_token = tokens["access_token"]
        
        # Tamper with token (change last character)
        tampered_token = access_token[:-1] + ("a" if access_token[-1] != "a" else "b")
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {tampered_token}"},
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_mobile_session_tracking(self, async_client: AsyncClient, create_test_user, db_session):
        """Test mobile session tracking and metadata."""
        
        # Login with mobile device
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "MyApp/1.0 (iPhone; iOS 14.0; iPhone12,1)",
                "X-Forwarded-For": "10.0.0.1",
            },
        )
        
        tokens = login_response.json()["tokens"]
        access_token = tokens["access_token"]
        
        # Make authenticated request
        await async_client.get(
            "/api/v1/users/profile",
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Forwarded-For": "10.0.0.1",
            },
        )
        
        # Check session metadata in database
        from app.models.session import Session
        from sqlalchemy import select
        
        result = await db_session.execute(
            select(Session).where(Session.user_id == create_test_user.id)
        )
        session = result.scalar_one()
        
        assert session.device_type == "mobile"
        assert "iPhone" in session.device_name
        assert session.ip_address == "10.0.0.1"
        assert "MyApp" in session.user_agent
    
    @pytest.mark.asyncio
    async def test_mobile_logout_all_sessions(self, async_client: AsyncClient, create_test_user):
        """Test logout from all mobile sessions."""
        
        # Create multiple mobile sessions
        session_tokens = []
        
        for i in range(3):
            login_response = await async_client.post(
                "/api/v1/auth/mobile/login",
                json={
                    "email": create_test_user.email,
                    "password": create_test_user.original_password,
                },
                headers={"User-Agent": f"TestApp/1.0 (Device-{i})"},
            )
            
            tokens = login_response.json()["tokens"]
            session_tokens.append(tokens["access_token"])
        
        # Logout from all sessions using first token
        logout_response = await async_client.post(
            "/api/v1/auth/logout-all",
            headers={"Authorization": f"Bearer {session_tokens[0]}"},
        )
        
        assert logout_response.status_code == 200
        
        # All tokens should be revoked
        for token in session_tokens:
            profile_response = await async_client.get(
                "/api/v1/users/profile",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert profile_response.status_code == 401


@pytest.mark.integration
@pytest.mark.auth
class TestMobileTokenValidation:
    """Test JWT token validation edge cases."""
    
    @pytest.mark.asyncio
    async def test_token_without_bearer_prefix(self, async_client: AsyncClient, create_test_user):
        """Test token without Bearer prefix."""
        
        # Login to get token
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )
        
        tokens = login_response.json()["tokens"]
        access_token = tokens["access_token"]
        
        # Try to use token without Bearer prefix
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": access_token},  # Missing "Bearer "
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_malformed_authorization_header(self, async_client: AsyncClient):
        """Test malformed Authorization header."""
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": "NotBearer token"},
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_empty_authorization_header(self, async_client: AsyncClient):
        """Test empty Authorization header."""
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": ""},
        )
        
        assert response.status_code == 401
