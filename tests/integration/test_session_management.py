"""Integration tests for session management."""

import pytest
from httpx import AsyncClient


@pytest.mark.integration
@pytest.mark.auth
class TestSessionListing:
    """Test session listing and information."""

    @pytest.mark.asyncio
    async def test_get_user_sessions(self, async_client: AsyncClient, auth_headers):
        """Test getting user's active sessions."""

        response = await async_client.get(
            "/api/v1/sessions/",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "sessions" in data
        assert "total" in data
        assert len(data["sessions"]) >= 1  # At least the current session

        session = data["sessions"][0]
        assert "id" in session
        assert "session_id" in session
        assert "device_name" in session
        assert "device_type" in session
        assert "user_agent" in session
        assert "ip_address" in session
        assert "is_current" in session
        assert "is_active" in session
        assert "is_revoked" in session
        assert "created_at" in session
        assert "expires_at" in session

    @pytest.mark.asyncio
    async def test_get_sessions_with_revoked(
        self, async_client: AsyncClient, auth_headers, create_test_user
    ):
        """Test getting sessions including revoked ones."""

        # Create and revoke a session first
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

        # Logout to revoke session
        await async_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        # Get sessions including revoked
        response = await async_client.get(
            "/api/v1/sessions/",
            params={"include_revoked": True},
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        # Should include revoked sessions
        revoked_sessions = [s for s in data["sessions"] if s["is_revoked"]]
        assert len(revoked_sessions) >= 1


@pytest.mark.integration
@pytest.mark.auth
class TestSessionRevocation:
    """Test session revocation functionality."""

    @pytest.mark.asyncio
    async def test_revoke_specific_session(
        self, async_client: AsyncClient, create_test_user, auth_headers
    ):
        """Test revoking a specific session."""

        # Create additional session
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )

        tokens = login_response.json()["tokens"]
        target_token = tokens["access_token"]

        # Get session ID
        sessions_response = await async_client.get(
            "/api/v1/sessions/",
            headers={"Authorization": f"Bearer {target_token}"},
        )

        sessions = sessions_response.json()["sessions"]
        target_session_id = sessions[0]["session_id"]

        # Revoke the specific session
        revoke_response = await async_client.delete(
            f"/api/v1/sessions/{target_session_id}",
            headers=auth_headers,  # Using different session to revoke
        )

        assert revoke_response.status_code == 200
        data = revoke_response.json()
        assert data["success"] is True
        assert "revoked" in data["message"]

        # Try to use revoked session
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {target_token}"},
        )

        assert profile_response.status_code == 401

    @pytest.mark.asyncio
    async def test_revoke_other_sessions(
        self, async_client: AsyncClient, create_test_user, auth_headers
    ):
        """Test revoking all other sessions except current."""

        # Create multiple sessions
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

        # Get current session ID (using auth_headers which is the "main" session)
        current_sessions_response = await async_client.get(
            "/api/v1/sessions/",
            headers=auth_headers,
        )

        current_session_id = current_sessions_response.json()["sessions"][0]["session_id"]

        # Revoke all other sessions
        revoke_response = await async_client.delete(
            "/api/v1/sessions/other",
            json={"current_session_id": current_session_id},
            headers=auth_headers,
        )

        assert revoke_response.status_code == 200
        data = revoke_response.json()
        assert data["success"] is True
        assert data["revoked_sessions"] >= 3

        # Current session should still work
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            headers=auth_headers,
        )
        assert profile_response.status_code == 200

        # Other sessions should be revoked
        for token in session_tokens:
            profile_response = await async_client.get(
                "/api/v1/users/profile",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert profile_response.status_code == 401

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_session(self, async_client: AsyncClient, auth_headers):
        """Test revoking non-existent session."""

        response = await async_client.delete(
            "/api/v1/sessions/nonexistent_session_id",
            headers=auth_headers,
        )

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_revoke_other_users_session(
        self, async_client: AsyncClient, create_test_user, create_admin_user, admin_auth_headers
    ):
        """Test that users cannot revoke other users' sessions."""

        # Create session for test user
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )

        tokens = login_response.json()["tokens"]

        # Get test user's session ID
        sessions_response = await async_client.get(
            "/api/v1/sessions/",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )

        session_id = sessions_response.json()["sessions"][0]["session_id"]

        # Try to revoke using admin user (different user)
        revoke_response = await async_client.delete(
            f"/api/v1/sessions/{session_id}",
            headers=admin_auth_headers,
        )

        assert revoke_response.status_code == 403  # Should be forbidden


@pytest.mark.integration
@pytest.mark.auth
class TestSessionStatistics:
    """Test session statistics and analytics."""

    @pytest.mark.asyncio
    async def test_get_session_stats(
        self, async_client: AsyncClient, auth_headers, create_test_user
    ):
        """Test getting session statistics."""

        # Create multiple sessions of different types
        # Mobile session
        await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )

        # Web session
        await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            },
        )

        # Get stats
        response = await async_client.get(
            "/api/v1/sessions/stats",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()

        assert data["success"] is True
        assert "stats" in data

        stats = data["stats"]
        assert "total_sessions" in stats
        assert "active_sessions" in stats
        assert "revoked_sessions" in stats
        assert "web_sessions" in stats
        assert "mobile_sessions" in stats
        assert "api_sessions" in stats

        assert stats["total_sessions"] >= 3  # At least auth_headers + mobile + web
        assert stats["active_sessions"] >= 3
        assert stats["mobile_sessions"] >= 1
        assert stats["web_sessions"] >= 1

    @pytest.mark.asyncio
    async def test_session_stats_after_revocation(
        self, async_client: AsyncClient, auth_headers, create_test_user
    ):
        """Test session stats after revoking sessions."""

        # Create session and revoke it
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )

        tokens = login_response.json()["tokens"]

        # Revoke the session
        await async_client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )

        # Get stats
        response = await async_client.get(
            "/api/v1/sessions/stats",
            headers=auth_headers,
        )

        assert response.status_code == 200
        stats = response.json()["stats"]

        assert stats["revoked_sessions"] >= 1


@pytest.mark.integration
@pytest.mark.auth
class TestSessionMetadata:
    """Test session metadata tracking."""

    @pytest.mark.asyncio
    async def test_session_device_tracking(self, async_client: AsyncClient, create_test_user):
        """Test session device information tracking."""

        # Login with specific device info
        response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "MyApp/1.0 (iPhone; iOS 14.0; iPhone12,1)",
                "X-Forwarded-For": "192.168.1.100",
            },
        )

        tokens = response.json()["tokens"]

        # Check session metadata
        sessions_response = await async_client.get(
            "/api/v1/sessions/",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )

        session = sessions_response.json()["sessions"][0]

        assert session["device_type"] == "mobile"
        assert "iPhone" in session["device_name"]
        # IP address may be overridden by test client, so just check it exists
        assert session["ip_address"] is not None
        assert "MyApp" in session["user_agent"]

    @pytest.mark.asyncio
    async def test_session_activity_tracking(
        self, async_client: AsyncClient, create_test_user, db_session
    ):
        """Test session last seen activity tracking."""

        # Login
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

        # Make API request to update last seen
        await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        # Check session activity in database
        from sqlalchemy import select

        from app.models.session import Session

        result = await db_session.execute(
            select(Session).where(Session.user_id == create_test_user.id)
        )
        session = result.scalars().first()

        assert session.last_seen_at is not None

    @pytest.mark.asyncio
    async def test_session_expiration_tracking(self, async_client: AsyncClient, create_test_user):
        """Test session expiration information."""

        # Login with remember me
        login_response = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
                "remember_me": True,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )

        tokens = login_response.json()["tokens"]

        # Check session expiration
        sessions_response = await async_client.get(
            "/api/v1/sessions/",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )

        session = sessions_response.json()["sessions"][0]

        assert session["expires_at"] is not None
        assert session["is_remember_me"] is True


@pytest.mark.integration
@pytest.mark.auth
@pytest.mark.security
class TestSessionSecurity:
    """Test session security features."""

    @pytest.mark.asyncio
    async def test_session_isolation(
        self, async_client: AsyncClient, create_test_user, create_admin_user
    ):
        """Test that users can only see their own sessions."""

        # Create session for test user
        test_login = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={"User-Agent": "TestApp/1.0 (iOS)"},
        )

        # Create session for admin user
        admin_login = await async_client.post(
            "/api/v1/auth/mobile/login",
            json={
                "email": create_admin_user.email,
                "password": create_admin_user.original_password,
            },
            headers={"User-Agent": "AdminApp/1.0 (iOS)"},
        )

        test_token = test_login.json()["tokens"]["access_token"]
        admin_token = admin_login.json()["tokens"]["access_token"]

        # Get sessions for each user
        test_sessions = await async_client.get(
            "/api/v1/sessions/",
            headers={"Authorization": f"Bearer {test_token}"},
        )

        admin_sessions = await async_client.get(
            "/api/v1/sessions/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        # Users should only see their own sessions
        test_session_ids = {s["session_id"] for s in test_sessions.json()["sessions"]}
        admin_session_ids = {s["session_id"] for s in admin_sessions.json()["sessions"]}

        assert test_session_ids.isdisjoint(admin_session_ids)

    @pytest.mark.asyncio
    async def test_concurrent_session_limit(self, async_client: AsyncClient, create_test_user):
        """Test concurrent session limits (if implemented)."""

        # Create many concurrent sessions
        session_tokens = []

        for i in range(10):  # Try to create 10 concurrent sessions
            response = await async_client.post(
                "/api/v1/auth/mobile/login",
                json={
                    "email": create_test_user.email,
                    "password": create_test_user.original_password,
                },
                headers={"User-Agent": f"TestApp/1.0 (Device-{i})"},
            )

            if response.status_code == 200:
                tokens = response.json()["tokens"]
                session_tokens.append(tokens["access_token"])

        # All sessions should work (no limit enforced in current implementation)
        for token in session_tokens:
            response = await async_client.get(
                "/api/v1/users/profile",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_session_cleanup_on_password_change(
        self, async_client: AsyncClient, create_test_user
    ):
        """Test that sessions are revoked when password changes."""

        # Create session
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

        # Change password
        await async_client.post(
            "/api/v1/users/change-password",
            json={
                "current_password": create_test_user.original_password,
                "new_password": "NewPassword123!",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        # Session should be revoked after password change
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        assert profile_response.status_code == 401
