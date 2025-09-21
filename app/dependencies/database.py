"""Database dependencies for FastAPI."""

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.database import get_async_session_local
from app.config.database import get_redis as _get_redis


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session dependency."""
    session_local = get_async_session_local()
    async with session_local() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_redis() -> aioredis.Redis:
    """Get Redis connection dependency."""
    return await _get_redis()
