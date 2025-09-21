"""Rate limiting middleware using Redis."""

import time
from collections.abc import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config.database import get_redis
from app.config.settings import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using sliding window algorithm."""

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through rate limiting middleware."""

        # Skip rate limiting for health checks
        if request.url.path in ["/health"]:
            return await call_next(request)

        # Get client identifier
        client_id = self._get_client_id(request)

        # Check rate limit
        rate_limit_ok = await self._check_rate_limit(client_id)

        if not rate_limit_ok:
            return JSONResponse(
                status_code=429,
                content={
                    "error": True,
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests",
                    "retry_after": 60,
                },
                headers={"Retry-After": "60"},
            )

        return await call_next(request)

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier for rate limiting."""

        # Use user ID if authenticated
        user = getattr(request.state, "user", None)
        if user:
            return f"user:{user.id}"

        # Use API key if present
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # Use first part of API key as identifier
            key_prefix = api_key.split("_")[0] if "_" in api_key else api_key[:10]
            return f"api_key:{key_prefix}"

        # Fall back to IP address
        client_ip = getattr(request.state, "client_ip", "unknown")
        return f"ip:{client_ip}"

    async def _check_rate_limit(self, client_id: str) -> bool:
        """Check if client is within rate limits using sliding window."""

        try:
            redis = await get_redis()
            current_time = int(time.time())
            window_size = 60  # 1 minute window

            # Redis key for this client
            key = f"rate_limit:{client_id}"

            # Use sliding window log algorithm
            async with redis.pipeline() as pipe:
                # Remove old entries outside the window
                pipe.zremrangebyscore(key, 0, current_time - window_size)

                # Count current requests in window
                pipe.zcard(key)

                # Add current request
                pipe.zadd(key, {str(current_time): current_time})

                # Set expiration for cleanup
                pipe.expire(key, window_size)

                results = await pipe.execute()

            # Check if under limit
            current_count = results[1]  # Count from zcard

            # Use different limits based on client type
            if client_id.startswith("user:"):
                limit = (
                    settings.RATE_LIMIT_REQUESTS_PER_MINUTE * 2
                )  # Higher limit for authenticated users
            elif client_id.startswith("api_key:"):
                # For API keys, get the limit from database
                limit = await self._get_api_key_rate_limit(client_id)
                if limit is None:
                    limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE * 5  # Default if not found
            else:
                limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE  # Base limit for IP

            return current_count < limit

        except Exception as e:
            # For testing, be strict about Redis availability
            if "redis" in str(e).lower() or "connection" in str(e).lower():
                # Redis unavailable - for strict testing, deny request
                return False
            # Other errors - allow the request
            return True

    async def _get_api_key_rate_limit(self, client_id: str) -> int:
        """Get rate limit for specific API key from database."""
        try:
            from sqlalchemy import select

            from app.config.database import get_async_session_local
            from app.models.api_key import APIKey

            # Extract API key from client_id (format: "api_key:prefix")
            api_key_prefix = client_id.replace("api_key:", "")

            session_local = get_async_session_local()
            async with session_local() as db:
                # Find API key by prefix and get its rate limit
                result = await db.execute(
                    select(APIKey.rate_limit_per_minute)
                    .where(APIKey.prefix == api_key_prefix)
                    .where(APIKey.is_active)
                )
                rate_limit = result.scalar_one_or_none()
                return (
                    rate_limit
                    if rate_limit is not None
                    else settings.RATE_LIMIT_REQUESTS_PER_MINUTE * 5
                )

        except Exception:
            return settings.RATE_LIMIT_REQUESTS_PER_MINUTE * 5
