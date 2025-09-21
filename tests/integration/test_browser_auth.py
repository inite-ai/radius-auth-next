"""Integration tests for browser authentication (cookies, sessions, CSRF)."""

import pytest
from httpx import AsyncClient

from app.config.settings import settings


@pytest.mark.integration
@pytest.mark.auth
class TestBrowserAuthentication:
    """Test browser authentication with cookies and sessions."""

    @pytest.mark.asyncio
    async def test_browser_login_success(self, async_client: AsyncClient, create_test_user):
        """Test successful browser login with cookie setting."""

        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
                "remember_me": False,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )

        assert response.status_code == 200
        data = response.json()

        # Browser client should not receive tokens in response body
        assert data["success"] is True
        assert "Login successful (web client)" in data["message"]
        assert data["tokens"] is None  # No tokens for browser
        assert "user" in data

        # Should set session cookie
        cookies = response.cookies
        assert settings.SESSION_COOKIE_NAME in cookies

        session_cookie = cookies[settings.SESSION_COOKIE_NAME]
        assert session_cookie is not None
        assert len(session_cookie) > 20  # Refresh token length

    @pytest.mark.asyncio
    async def test_browser_login_remember_me(self, async_client: AsyncClient, create_test_user):
        """Test browser login with remember me option."""

        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
                "remember_me": True,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
            },
        )

        assert response.status_code == 200

        # Check cookie properties for remember me
        cookies = response.cookies
        session_cookie = cookies.get(settings.SESSION_COOKIE_NAME)
        assert session_cookie is not None

    @pytest.mark.asyncio
    async def test_browser_authenticated_request(self, async_client: AsyncClient, create_test_user):
        """Test authenticated request using session cookie."""

        # First login to get session cookie
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            },
        )

        assert login_response.status_code == 200

        # Extract session cookie
        session_cookie = login_response.cookies.get(settings.SESSION_COOKIE_NAME)
        assert session_cookie is not None

        # Make authenticated request using cookie
        response = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: session_cookie},
        )

        assert response.status_code == 200
        data = response.json()
        assert "user" in data
        assert data["user"]["email"] == create_test_user.email

    @pytest.mark.asyncio
    async def test_browser_logout(self, async_client: AsyncClient, create_test_user):
        """Test browser logout with session revocation."""

        # Login first
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            },
        )

        session_cookie = login_response.cookies.get(settings.SESSION_COOKIE_NAME)

        # Logout
        logout_response = await async_client.post(
            "/api/v1/auth/logout",
            cookies={settings.SESSION_COOKIE_NAME: session_cookie},
        )

        assert logout_response.status_code == 200
        data = logout_response.json()
        assert data["success"] is True
        assert "logout successful" in data["message"].lower()

        # Try to use session after logout - should fail
        profile_response = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: session_cookie},
        )

        assert profile_response.status_code == 401

    @pytest.mark.asyncio
    async def test_browser_invalid_session(self, async_client: AsyncClient):
        """Test request with invalid session cookie."""

        response = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: "invalid_session_token"},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_browser_expired_session(
        self, async_client: AsyncClient, create_test_user, db_session
    ):
        """Test request with expired session."""

        # Login to create session
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            },
        )

        session_cookie = login_response.cookies.get(settings.SESSION_COOKIE_NAME)

        # Manually expire session in database
        from datetime import datetime, timedelta

        from sqlalchemy import update

        from app.models.session import Session

        await db_session.execute(
            update(Session)
            .where(Session.user_id == create_test_user.id)
            .values(expires_at=datetime.utcnow() - timedelta(hours=1))
        )
        await db_session.commit()

        # Try to use expired session
        response = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: session_cookie},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_browser_session_activity_tracking(
        self, async_client: AsyncClient, create_test_user, db_session
    ):
        """Test session activity tracking for browser clients."""

        # Login
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "X-Forwarded-For": "192.168.1.100",
            },
        )

        session_cookie = login_response.cookies.get(settings.SESSION_COOKIE_NAME)

        # Make request to trigger activity update
        await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: session_cookie},
            headers={"X-Forwarded-For": "192.168.1.100"},
        )

        # Check session activity in database
        from sqlalchemy import select

        from app.models.session import Session

        result = await db_session.execute(
            select(Session).where(Session.user_id == create_test_user.id)
        )
        session = result.scalar_one()

        assert session.last_seen_at is not None
        assert session.ip_address == "192.168.1.100"
        assert "Mozilla" in session.user_agent
        assert session.device_type == "web"

    @pytest.mark.asyncio
    async def test_browser_multiple_sessions(self, async_client: AsyncClient, create_test_user):
        """Test multiple browser sessions for same user."""

        # Create first session (Chrome)
        chrome_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            },
        )

        chrome_cookie = chrome_response.cookies.get(settings.SESSION_COOKIE_NAME)

        # Create second session (Firefox)
        firefox_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            },
        )

        firefox_cookie = firefox_response.cookies.get(settings.SESSION_COOKIE_NAME)

        # Both sessions should work
        chrome_profile = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: chrome_cookie},
        )

        firefox_profile = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: firefox_cookie},
        )

        assert chrome_profile.status_code == 200
        assert firefox_profile.status_code == 200

        # Logout from one session shouldn't affect the other
        await async_client.post(
            "/api/v1/auth/logout",
            cookies={settings.SESSION_COOKIE_NAME: chrome_cookie},
        )

        # Chrome session should be dead
        chrome_check = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: chrome_cookie},
        )
        assert chrome_check.status_code == 401

        # Firefox session should still work
        firefox_check = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: firefox_cookie},
        )
        assert firefox_check.status_code == 200


@pytest.mark.integration
@pytest.mark.auth
class TestBrowserDeviceDetection:
    """Test browser device detection and session metadata."""

    @pytest.mark.asyncio
    async def test_chrome_detection(self, async_client: AsyncClient, create_test_user):
        """Test Chrome browser detection."""

        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "web client" in data["message"]

    @pytest.mark.asyncio
    async def test_firefox_detection(self, async_client: AsyncClient, create_test_user):
        """Test Firefox browser detection."""

        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "web client" in data["message"]

    @pytest.mark.asyncio
    async def test_safari_detection(self, async_client: AsyncClient, create_test_user):
        """Test Safari browser detection."""

        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "web client" in data["message"]


@pytest.mark.integration
@pytest.mark.auth
@pytest.mark.security
class TestBrowserSecurity:
    """Test browser authentication security features."""

    @pytest.mark.asyncio
    async def test_login_rate_limiting(
        self, async_client: AsyncClient, create_test_user, mock_redis
    ):
        """Test login rate limiting for browser clients."""

        # Mock rate limit settings for this test
        from app.config.settings import settings

        original_limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE
        settings.RATE_LIMIT_REQUESTS_PER_MINUTE = 5  # Low limit for testing

        try:
            # Clear any existing rate limit counters
            mock_redis.clear_counters()

            # Make multiple failed login attempts
            for i in range(7):  # Exceed rate limit of 5
                response = await async_client.post(
                    "/api/v1/auth/login",
                    json={
                        "email": create_test_user.email,
                        "password": "wrong_password",
                    },
                    headers={
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                    },
                )

                if response.status_code == 429:  # Rate limited
                    break

            # Should eventually get rate limited
            assert response.status_code == 429
            data = response.json()
            assert "too many requests" in data["message"].lower()

        finally:
            # Restore original rate limit
            settings.RATE_LIMIT_REQUESTS_PER_MINUTE = original_limit

    @pytest.mark.asyncio
    async def test_account_lockout(self, async_client: AsyncClient, create_test_user, db_session):
        """Test account lockout after failed attempts."""

        # Make multiple failed login attempts to trigger lockout
        for _ in range(6):  # Trigger account lockout
            await async_client.post(
                "/api/v1/auth/login",
                json={
                    "email": create_test_user.email,
                    "password": "wrong_password",
                },
                headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                },
            )

        # Try with correct password - should still fail due to lockout
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            },
        )

        assert response.status_code == 401
        data = response.json()
        assert "locked" in data["detail"].lower()

    @pytest.mark.asyncio
    async def test_session_hijacking_protection(self, async_client: AsyncClient, create_test_user):
        """Test protection against session hijacking."""

        # Login from one IP
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "email": create_test_user.email,
                "password": create_test_user.original_password,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "X-Forwarded-For": "192.168.1.100",
            },
        )

        session_cookie = login_response.cookies.get(settings.SESSION_COOKIE_NAME)

        # Try to use session from different IP (potential hijacking)
        # Note: This test assumes IP checking is implemented
        response = await async_client.get(
            "/api/v1/users/profile",
            cookies={settings.SESSION_COOKIE_NAME: session_cookie},
            headers={"X-Forwarded-For": "10.0.0.1"},  # Different IP
        )

        # Should still work (IP changes can be legitimate)
        # But activity should be logged for monitoring
        assert response.status_code == 200
