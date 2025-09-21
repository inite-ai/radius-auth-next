"""Database configuration and dependencies."""

import redis.asyncio as aioredis
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .settings import settings

# SQLAlchemy setup
Base = declarative_base()

# Global engine variables (lazy initialization)
async_engine = None
sync_engine = None
AsyncSessionLocal = None
SessionLocal = None


def get_async_engine():
    """Get or create async engine."""
    global async_engine
    if async_engine is None:
        async_engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
    return async_engine


def get_sync_engine():
    """Get or create sync engine."""
    global sync_engine
    if sync_engine is None:
        sync_engine = create_engine(
            settings.DATABASE_URL_SYNC,
            echo=settings.DEBUG,
            pool_pre_ping=True,
            pool_recycle=3600,
        )
    return sync_engine


def get_async_session_local():
    """Get or create async session factory."""
    global AsyncSessionLocal
    if AsyncSessionLocal is None:
        AsyncSessionLocal = async_sessionmaker(
            get_async_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return AsyncSessionLocal


def get_session_local():
    """Get or create sync session factory."""
    global SessionLocal
    if SessionLocal is None:
        SessionLocal = sessionmaker(
            get_sync_engine(),
            autocommit=False,
            autoflush=False,
        )
    return SessionLocal


# Redis connection
redis_pool = None


async def init_redis():
    """Initialize Redis connection pool."""
    global redis_pool
    redis_pool = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        max_connections=20,
    )
    return redis_pool


async def close_redis():
    """Close Redis connection pool."""
    global redis_pool
    if redis_pool:
        await redis_pool.close()


async def get_db() -> AsyncSession:
    """Get database session dependency."""
    session_local = get_async_session_local()
    async with session_local() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_redis() -> aioredis.Redis:
    """Get Redis connection dependency."""
    global redis_pool
    if not redis_pool:
        redis_pool = await init_redis()
    return redis_pool


def reset_engines():
    """Reset all engines and session factories for testing."""
    global async_engine, sync_engine, AsyncSessionLocal, SessionLocal
    async_engine = None
    sync_engine = None
    AsyncSessionLocal = None
    SessionLocal = None
