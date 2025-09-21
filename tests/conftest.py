"""Test configuration and fixtures."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient

from app.config.settings import Settings, settings
from app.main import app

# Import all models to register them with Base.metadata
from app.models import *  # noqa: F403, F401
from app.models.base import Base


# Test settings
@pytest.fixture(scope="session", autouse=True)
def setup_test_settings():
    """Setup test settings configuration."""
    # Override global settings for testing
    settings.TESTING = True
    settings.DATABASE_URL = "sqlite+aiosqlite:///./test.db"
    settings.DATABASE_URL_SYNC = "sqlite:///./test.db"
    settings.REDIS_URL = "redis://localhost:6379/15"

    # Reset engines to pick up new settings
    from app.config.database import reset_engines

    reset_engines()

    yield


@pytest.fixture(scope="session")
def test_settings():
    """Test settings configuration."""
    return Settings(
        DATABASE_URL="sqlite+aiosqlite:///./test.db",
        REDIS_URL="redis://localhost:6379/15",
        JWT_SECRET_KEY="test-secret-key-super-long-for-testing-purposes-only",
        CSRF_SECRET_KEY="test-csrf-secret-key-super-long-for-testing-purposes-only",
        TESTING=True,
        API_TITLE="Test API",
        LOG_LEVEL="DEBUG",
    )


# Setup database tables for tests
@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_database():
    """Setup test database with tables."""
    from app.config.database import get_async_engine

    engine = get_async_engine()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        print(f"Created tables: {list(Base.metadata.tables.keys())}")

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()

    # Clean up test database file
    try:
        os.remove("./test.db")
    except FileNotFoundError:
        pass


# Test client
@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """Create test client."""
    with TestClient(app) as test_client:
        yield test_client


# Async test client
@pytest_asyncio.fixture(scope="function")
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Create async test client."""
    from httpx import ASGITransport

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# Test user data
@pytest.fixture
def test_user_data():
    """Test user data."""
    import uuid

    unique_id = str(uuid.uuid4())[:8]
    return {
        "email": f"test_{unique_id}@example.com",
        "password": "TestPassword123!",
        "first_name": "Test",
        "last_name": "User",
        "username": f"testuser_{unique_id}",
    }


@pytest.fixture
def admin_user_data():
    """Admin user data."""
    import uuid

    unique_id = str(uuid.uuid4())[:8]
    return {
        "email": f"admin_{unique_id}@example.com",
        "password": "AdminPassword123!",
        "first_name": "Admin",
        "last_name": "User",
        "username": f"admin_{unique_id}",
        "is_superuser": True,
    }


@pytest.fixture
def test_organization_data():
    """Test organization data."""
    return {
        "name": "Test Organization",
        "slug": "test-org",
        "description": "Test organization for testing",
    }


@pytest.fixture
def oauth_client_data():
    """OAuth client data."""
    return {
        "name": "Test OAuth Client",
        "description": "OAuth client for testing",
        "redirect_uris": ["http://localhost:8000/callback"],
        "allowed_scopes": ["profile", "email", "organizations"],
        "is_confidential": True,
    }


# Create test user helper
@pytest_asyncio.fixture
async def create_test_user(test_user_data):
    """Create test user in database."""
    from app.config.database import get_async_session_local
    from app.models.user import User
    from app.utils.security import hash_password

    user_data = test_user_data.copy()
    password = user_data.pop("password")

    # Create user in the same database session that the app uses
    session_local = get_async_session_local()
    async with session_local() as db_session:
        try:
            user = User(
                **user_data,
                password_hash=hash_password(password),
                is_verified=True,
                is_active=True,
            )

            db_session.add(user)
            await db_session.commit()
            await db_session.refresh(user)

            # Add original password for testing
            user.original_password = password

            yield user

        except Exception as e:
            await db_session.rollback()
            print(f"Error creating test user: {e}")
            raise
        finally:
            # Clean up will happen automatically when database is dropped in test teardown
            pass


# Create admin user helper
@pytest_asyncio.fixture
async def create_admin_user(admin_user_data):
    """Create admin user in database."""
    from app.config.database import get_async_session_local
    from app.models.user import User
    from app.utils.security import hash_password

    user_data = admin_user_data.copy()
    password = user_data.pop("password")

    # Remove fields that we'll set explicitly
    user_data.pop("is_superuser", None)
    user_data.pop("is_verified", None)
    user_data.pop("is_active", None)

    session_local = get_async_session_local()
    async with session_local() as db_session:
        try:
            user = User(
                **user_data,
                password_hash=hash_password(password),
                is_verified=True,
                is_active=True,
                is_superuser=True,
            )

            db_session.add(user)
            await db_session.commit()
            await db_session.refresh(user)

            # Add original password for testing
            user.original_password = password

            yield user

        except Exception as e:
            await db_session.rollback()
            print(f"Error creating admin user: {e}")
            raise
        finally:
            try:
                await db_session.delete(user)
                await db_session.commit()
            except:
                pass


# Create test organization helper
@pytest_asyncio.fixture
async def create_test_organization(db_session, test_organization_data, create_test_user):
    """Create test organization with user membership."""
    from app.models.membership import Membership, Role
    from app.models.organization import Organization

    org = Organization(**test_organization_data)

    db_session.add(org)
    await db_session.flush()

    # Add user as owner
    membership = Membership(
        user_id=create_test_user.id,
        organization_id=org.id,
        role=Role.OWNER,
        is_active=True,
    )

    db_session.add(membership)
    await db_session.commit()
    await db_session.refresh(org)

    return org


# Authentication helpers
@pytest_asyncio.fixture
async def auth_headers(async_client, create_test_user):
    """Get authentication headers for test user."""

    # Login to get JWT token using universal login endpoint
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": create_test_user.email,
            "password": create_test_user.original_password,
        },
        headers={"User-Agent": "TestApp/1.0 (Mobile)"},  # Mobile user-agent for JWT tokens
    )

    assert login_response.status_code == 200
    data = login_response.json()
    access_token = data["tokens"]["access_token"]

    return {"Authorization": f"Bearer {access_token}"}


@pytest_asyncio.fixture
async def admin_auth_headers(async_client, create_admin_user):
    """Get authentication headers for admin user."""

    # Login to get JWT token
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={
            "email": create_admin_user.email,
            "password": create_admin_user.original_password,
        },
        headers={"User-Agent": "TestApp/1.0 (Mobile)"},
    )

    assert login_response.status_code == 200
    data = login_response.json()
    access_token = data["tokens"]["access_token"]

    return {"Authorization": f"Bearer {access_token}"}


# OAuth client helper
@pytest_asyncio.fixture
async def create_oauth_client(db_session, oauth_client_data, create_admin_user):
    """Create OAuth client."""
    from app.services.oauth_service import OAuthService

    oauth_service = OAuthService(db_session)
    client, client_secret = await oauth_service.create_client(
        name=oauth_client_data["name"],
        redirect_uris=oauth_client_data["redirect_uris"],
        allowed_scopes=oauth_client_data["allowed_scopes"],
        description=oauth_client_data["description"],
        is_confidential=oauth_client_data["is_confidential"],
        user_id=create_admin_user.id,
    )

    # Add client secret for testing
    client.client_secret = client_secret

    return client


# API key helper
@pytest_asyncio.fixture
async def create_api_key(create_test_user):
    """Create API key for test user."""
    from app.config.database import get_async_session_local
    from app.models.api_key import APIKey
    from app.utils.security import generate_api_key, hash_token

    # Generate API key
    api_key = generate_api_key(prefix="test", length=32)
    key_hash = hash_token(api_key)

    # Create API key record
    session_local = get_async_session_local()
    async with session_local() as db_session:
        api_key_record = APIKey(
            user_id=create_test_user.id,
            name="Test API Key",
            key_hash=key_hash,
            prefix="test",
            scopes_list=["profile", "organizations"],
            rate_limit_per_minute=100,  # High limit to avoid rate limiting in usage tests
        )

        db_session.add(api_key_record)
        await db_session.commit()
        await db_session.refresh(api_key_record)

        # Add actual key for testing
        api_key_record.api_key = api_key

        return api_key_record


@pytest_asyncio.fixture
async def create_api_key_with_low_rate_limit(create_test_user):
    """Create an API key with low rate limit for rate limiting tests."""
    from app.config.database import get_async_session_local
    from app.models.api_key import APIKey
    from app.utils.security import generate_api_key, hash_token

    # Generate API key
    api_key = generate_api_key(prefix="test", length=32)
    key_hash = hash_token(api_key)

    # Create API key record with low rate limit
    session_local = get_async_session_local()
    async with session_local() as db_session:
        api_key_record = APIKey(
            user_id=create_test_user.id,
            name="Test API Key",
            key_hash=key_hash,
            prefix="test",
            scopes_list=["profile", "organizations"],
            rate_limit_per_minute=2,  # Very low limit for rate limiting tests
        )

        db_session.add(api_key_record)
        await db_session.commit()
        await db_session.refresh(api_key_record)

        # Add actual key for testing
        api_key_record.api_key = api_key

        return api_key_record


# Database session for tests
@pytest_asyncio.fixture
async def db_session():
    """Create async database session for testing."""
    from app.config.database import get_async_session_local

    session_local = get_async_session_local()
    async with session_local() as session:
        yield session


@pytest_asyncio.fixture
async def mock_redis():
    """Mock Redis for rate limiting tests."""
    # Shared counter to track requests per client across all pipeline instances
    request_counters = {}

    class MockRedis:
        def __init__(self):
            self.counters = request_counters

        def clear_counters(self):
            """Clear all request counters for fresh test."""
            self.counters.clear()

        def pipeline(self):
            return MockPipeline(self.counters)

    class MockPipeline:
        def __init__(self, counters):
            self.operations = []
            self.key = None
            self.counters = counters

        def __aenter__(self):
            return self

        def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        def zremrangebyscore(self, key, min_score, max_score):
            self.key = key
            self.operations.append(("zremrangebyscore", key, min_score, max_score))
            return self

        def zcard(self, key):
            self.key = key
            self.operations.append(("zcard", key))
            return self

        def zadd(self, key, mapping):
            self.key = key
            self.operations.append(("zadd", key, mapping))
            return self

        def expire(self, key, seconds):
            self.operations.append(("expire", key, seconds))
            return self

        async def execute(self):
            # Simplified mock that just increments counter for each request
            # The middleware expects: [removed_count, current_count, added_count, expire_result]

            # Find the key from operations
            key = None
            for op, *args in self.operations:
                if args:
                    key = args[0]
                    break

            if not key:
                return [0, 0, 1, 1]  # Default response

            # Initialize counter if not exists
            if key not in self.counters:
                self.counters[key] = 0

            # Get current count BEFORE increment
            current_count = self.counters[key]

            # Increment for this request
            self.counters[key] += 1

            # Return results in order: zremrangebyscore, zcard, zadd, expire
            return [0, current_count, 1, 1]

    # Mock get_redis function
    import app.config.database

    original_get_redis = app.config.database.get_redis

    # Create fresh MockRedis instance for each test
    redis_instance = MockRedis()

    async def mock_get_redis():
        return redis_instance

    app.config.database.get_redis = mock_get_redis

    yield redis_instance

    # Restore original
    app.config.database.get_redis = original_get_redis


# Event loop for session scope
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for session scope."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
