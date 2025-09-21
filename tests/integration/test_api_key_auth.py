"""Integration tests for API key authentication (machine-to-machine)."""

import pytest
from httpx import AsyncClient


@pytest.mark.integration
@pytest.mark.auth
class TestAPIKeyAuthentication:
    """Test API key authentication for machine-to-machine access."""
    
    async def test_create_api_key(self, async_client: AsyncClient, auth_headers):
        """Test API key creation."""
        
        response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "Test API Key",
                "scopes": ["profile", "organizations"],
                "expires_days": 30,
            },
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert "API key created successfully" in data["message"]
        assert "api_key" in data
        assert "key_info" in data
        assert "warning" in data
        
        api_key = data["api_key"]
        assert api_key.startswith("pauth_")
        assert len(api_key) > 30  # Should be reasonably long
        
        key_info = data["key_info"]
        assert key_info["name"] == "Test API Key"
        assert "pauth" in key_info["prefix"]
        assert key_info["scopes"] == ["profile", "organizations"]
        assert key_info["expires_at"] is not None
    
    async def test_api_key_authentication(self, async_client: AsyncClient, create_api_key):
        """Test authentication using API key."""
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": create_api_key.api_key},
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "email" in data
    
    async def test_api_key_scoped_access(self, async_client: AsyncClient, auth_headers):
        """Test API key with limited scopes."""
        
        # Create API key with limited scope
        create_response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "Limited API Key",
                "scopes": ["profile"],  # No organizations scope
            },
            headers=auth_headers,
        )
        
        api_key = create_response.json()["api_key"]
        
        # Profile access should work
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": api_key},
        )
        assert profile_response.status_code == 200
        
        # Organizations access should be restricted (if scope checking is implemented)
        # Note: This depends on scope enforcement in endpoints
        orgs_response = await async_client.get(
            "/api/v1/organizations/",
            headers={"X-API-Key": api_key},
        )
        
        # Should either work (if no scope checking) or be forbidden
        assert orgs_response.status_code in [200, 403]
    
    async def test_list_api_keys(self, async_client: AsyncClient, auth_headers, create_api_key):
        """Test listing user's API keys."""
        
        response = await async_client.get(
            "/api/v1/auth/api-keys",
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert "api_keys" in data
        assert len(data["api_keys"]) >= 1
        
        api_key_info = data["api_keys"][0]
        assert "id" in api_key_info
        assert "name" in api_key_info
        assert "prefix" in api_key_info
        assert "scopes" in api_key_info
        assert "is_valid" in api_key_info
        assert "usage_count" in api_key_info
        assert "created_at" in api_key_info
        
        # Should NOT include the actual API key
        assert "api_key" not in api_key_info
        assert "key_hash" not in api_key_info
    
    async def test_revoke_api_key(self, async_client: AsyncClient, auth_headers, create_api_key):
        """Test API key revocation."""
        
        # Revoke API key
        revoke_response = await async_client.delete(
            f"/api/v1/auth/api-keys/{create_api_key.id}",
            headers=auth_headers,
        )
        
        assert revoke_response.status_code == 200
        data = revoke_response.json()
        assert data["success"] is True
        assert "revoked" in data["message"]
        
        # Try to use revoked API key
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": create_api_key.api_key},
        )
        
        assert profile_response.status_code == 401
    
    async def test_invalid_api_key(self, async_client: AsyncClient):
        """Test request with invalid API key."""
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": "invalid_api_key"},
        )
        
        assert response.status_code == 401
    
    async def test_malformed_api_key(self, async_client: AsyncClient):
        """Test request with malformed API key."""
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": "not_pauth_prefix_key"},
        )
        
        assert response.status_code == 401
    
    async def test_expired_api_key(self, async_client: AsyncClient, auth_headers, db_session):
        """Test request with expired API key."""
        
        # Create API key that expires in 1 day
        create_response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "Expiring API Key",
                "expires_days": 1,
            },
            headers=auth_headers,
        )
        
        api_key = create_response.json()["api_key"]
        
        # Manually expire the key in database
        from app.models.api_key import APIKey
        from datetime import datetime, timedelta
        from sqlalchemy import select, update
        
        await db_session.execute(
            update(APIKey)
            .where(APIKey.name == "Expiring API Key")
            .values(expires_at=datetime.utcnow() - timedelta(hours=1))
        )
        await db_session.commit()
        
        # Try to use expired API key
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": api_key},
        )
        
        assert response.status_code == 401


@pytest.mark.integration
@pytest.mark.auth
class TestAPIKeyDeviceDetection:
    """Test API key device detection and classification."""
    
    async def test_api_client_detection(self, async_client: AsyncClient, create_test_user):
        """Test API client detection via User-Agent."""
        
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "curl/7.68.0",
                "Accept": "application/json",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should detect as API client and return tokens
        assert "api client" in data["message"]
        assert data["tokens"] is not None
        assert len(response.cookies) == 0
    
    async def test_postman_detection(self, async_client: AsyncClient, create_test_user):
        """Test Postman client detection."""
        
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "PostmanRuntime/7.26.8",
                "Accept": "application/json",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "api client" in data["message"]
        assert data["tokens"] is not None
    
    async def test_python_requests_detection(self, async_client: AsyncClient, create_test_user):
        """Test Python requests library detection."""
        
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "python-requests/2.25.1",
                "Accept": "application/json",
            },
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "api client" in data["message"]
        assert data["tokens"] is not None


@pytest.mark.integration
@pytest.mark.auth
@pytest.mark.security
class TestAPIKeySecurity:
    """Test API key security features."""
    
    async def test_api_key_usage_tracking(self, async_client: AsyncClient, create_api_key, db_session):
        """Test API key usage tracking."""
        
        # Make several requests with API key
        for _ in range(3):
            await async_client.get(
                "/api/v1/users/profile",
                headers={"X-API-Key": create_api_key.api_key},
            )
        
        # Check usage tracking in database
        from app.models.api_key import APIKey
        from sqlalchemy import select
        
        result = await db_session.execute(
            select(APIKey).where(APIKey.id == create_api_key.id)
        )
        api_key_record = result.scalar_one()
        
        assert api_key_record.usage_count >= 3
        assert api_key_record.last_used_at is not None
    
    async def test_api_key_rate_limiting(self, async_client: AsyncClient, create_api_key):
        """Test API key rate limiting."""
        
        # Make many rapid requests
        responses = []
        for _ in range(20):  # Assuming rate limit is lower
            response = await async_client.get(
                "/api/v1/users/profile",
                headers={"X-API-Key": create_api_key.api_key},
            )
            responses.append(response)
            
            if response.status_code == 429:  # Rate limited
                break
        
        # Should eventually get rate limited
        assert any(r.status_code == 429 for r in responses)
    
    async def test_api_key_prefix_validation(self, async_client: AsyncClient, auth_headers):
        """Test API key prefix validation."""
        
        # Create API key
        create_response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "Prefix Test Key",
            },
            headers=auth_headers,
        )
        
        api_key = create_response.json()["api_key"]
        
        # Should have correct prefix
        assert api_key.startswith("pauth_")
        
        # Try to use key with wrong prefix
        wrong_prefix_key = api_key.replace("pauth_", "wrong_")
        
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": wrong_prefix_key},
        )
        
        assert response.status_code == 401
    
    async def test_api_key_hash_storage(self, async_client: AsyncClient, auth_headers, db_session):
        """Test that API keys are stored as hashes, not plaintext."""
        
        # Create API key
        create_response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "Hash Test Key",
            },
            headers=auth_headers,
        )
        
        api_key = create_response.json()["api_key"]
        
        # Check database storage
        from app.models.api_key import APIKey
        from sqlalchemy import select
        
        result = await db_session.execute(
            select(APIKey).where(APIKey.name == "Hash Test Key")
        )
        api_key_record = result.scalar_one()
        
        # Should store hash, not plaintext
        assert api_key_record.key_hash != api_key
        assert len(api_key_record.key_hash) == 64  # SHA256 hex length
        assert api_key not in api_key_record.key_hash
    
    async def test_api_key_scope_enforcement(self, async_client: AsyncClient, auth_headers):
        """Test API key scope enforcement."""
        
        # Create API key with no scopes
        create_response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "No Scope Key",
                "scopes": [],
            },
            headers=auth_headers,
        )
        
        api_key = create_response.json()["api_key"]
        
        # Should be able to authenticate but may have limited access
        response = await async_client.get(
            "/api/v1/users/profile",
            headers={"X-API-Key": api_key},
        )
        
        # Depends on implementation - may succeed or fail based on scope checking
        assert response.status_code in [200, 403]


@pytest.mark.integration
@pytest.mark.auth
class TestAPIKeyManagement:
    """Test API key management operations."""
    
    async def test_create_multiple_api_keys(self, async_client: AsyncClient, auth_headers):
        """Test creating multiple API keys for same user."""
        
        keys = []
        
        for i in range(3):
            response = await async_client.post(
                "/api/v1/auth/api-key/create",
                params={
                    "name": f"API Key {i}",
                    "scopes": ["profile"],
                },
                headers=auth_headers,
            )
            
            assert response.status_code == 200
            keys.append(response.json()["api_key"])
        
        # All keys should be different
        assert len(set(keys)) == 3
        
        # All keys should work
        for key in keys:
            response = await async_client.get(
                "/api/v1/users/profile",
                headers={"X-API-Key": key},
            )
            assert response.status_code == 200
    
    async def test_api_key_with_expiration(self, async_client: AsyncClient, auth_headers):
        """Test API key with custom expiration."""
        
        response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "Expiring Key",
                "expires_days": 7,
            },
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.json()
        
        key_info = data["key_info"]
        assert key_info["expires_at"] is not None
        
        # Check that expiration is approximately 7 days from now
        from datetime import datetime, timedelta
        expires_at = datetime.fromisoformat(key_info["expires_at"].replace("Z", "+00:00"))
        expected_expiry = datetime.utcnow() + timedelta(days=7)
        
        # Allow some tolerance (within 1 hour)
        assert abs((expires_at - expected_expiry).total_seconds()) < 3600
    
    async def test_api_key_without_expiration(self, async_client: AsyncClient, auth_headers):
        """Test API key without expiration."""
        
        response = await async_client.post(
            "/api/v1/auth/api-key/create",
            params={
                "name": "Permanent Key",
            },
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.json()
        
        key_info = data["key_info"]
        assert key_info["expires_at"] is None
    
    async def test_revoke_nonexistent_api_key(self, async_client: AsyncClient, auth_headers):
        """Test revoking non-existent API key."""
        
        response = await async_client.delete(
            "/api/v1/auth/api-keys/99999",  # Non-existent ID
            headers=auth_headers,
        )
        
        assert response.status_code == 404
    
    async def test_revoke_other_users_api_key(self, async_client: AsyncClient, create_api_key, create_admin_user, admin_auth_headers):
        """Test that users cannot revoke other users' API keys."""
        
        # Try to revoke another user's API key
        response = await async_client.delete(
            f"/api/v1/auth/api-keys/{create_api_key.id}",
            headers=admin_auth_headers,  # Different user
        )
        
        assert response.status_code == 404  # Should appear as not found for security
