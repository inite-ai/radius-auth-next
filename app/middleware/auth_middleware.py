"""Authentication middleware for FastAPI."""

import time
from collections.abc import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.exceptions import BaseAuthException


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware for authentication and request processing."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through authentication middleware."""

        # Add request start time for timing
        request.state.start_time = time.time()

        # Add client IP to request state
        # Try to get IP from headers first (for proxies)
        forwarded_ip = request.headers.get("X-Forwarded-For", "").split(",")[
            0
        ].strip() or request.headers.get("X-Real-IP", "")

        if forwarded_ip:
            request.state.client_ip = forwarded_ip
        elif request.client:
            request.state.client_ip = request.client.host
        else:
            request.state.client_ip = "unknown"

        # Add user agent to request state
        request.state.user_agent = request.headers.get("User-Agent", "")

        try:
            # Process request
            response = await call_next(request)

            # Add timing header
            process_time = time.time() - request.state.start_time
            response.headers["X-Process-Time"] = str(process_time)

            return response

        except BaseAuthException as e:
            # Handle authentication/authorization exceptions
            return JSONResponse(
                status_code=401 if "authentication" in e.error_code.lower() else 403,
                content={
                    "error": True,
                    "error_code": e.error_code,
                    "message": e.message,
                    "details": e.details,
                },
            )

        except Exception:
            # Handle unexpected exceptions
            return JSONResponse(
                status_code=500,
                content={
                    "error": True,
                    "error_code": "INTERNAL_ERROR",
                    "message": "Internal server error",
                },
            )
