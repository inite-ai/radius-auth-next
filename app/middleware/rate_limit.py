"""Rate limiting middleware using Redis."""

import time
from typing import Callable

import redis.asyncio as aioredis
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config.database import get_redis
from app.config.settings import settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using sliding window algorithm."""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through rate limiting middleware."""
        
        # Skip rate limiting for health checks
        if request.url.path in ["/health"]:
            return await call_next(request)
        
        # Get client identifier
        client_id = self._get_client_id(request)
        
        # Check rate limit
        if not await self._check_rate_limit(client_id):
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
                limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE * 2  # Higher limit for authenticated users
            elif client_id.startswith("api_key:"):
                limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE * 5  # Highest limit for API keys
            else:
                limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE  # Base limit for IP
            
            return current_count < limit
            
        except Exception:
            # If Redis is unavailable, allow the request
            return True
