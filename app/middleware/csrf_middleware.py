"""CSRF protection middleware."""

from collections.abc import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config.settings import settings
from app.utils.security import constant_time_compare, generate_csrf_token


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection middleware for browser requests."""

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
    EXCLUDED_PATHS = {"/health", "/api/v1/docs", "/api/v1/redoc", "/api/v1/openapi.json"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request through CSRF middleware."""

        # Skip CSRF protection for certain conditions
        if self._should_skip_csrf(request):
            return await call_next(request)

        # Safe methods don't need CSRF protection
        if request.method in self.SAFE_METHODS:
            response = await call_next(request)
            # Set CSRF token cookie for subsequent requests
            self._set_csrf_cookie(response)
            return response

        # Check CSRF token for unsafe methods
        if not self._validate_csrf_token(request):
            return JSONResponse(
                status_code=403,
                content={
                    "error": True,
                    "error_code": "CSRF_TOKEN_INVALID",
                    "message": "CSRF token validation failed",
                },
            )

        response = await call_next(request)
        self._set_csrf_cookie(response)
        return response

    def _should_skip_csrf(self, request: Request) -> bool:
        """Check if CSRF protection should be skipped."""

        # Skip for excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return True

        # Skip for API key authentication
        if request.headers.get("X-API-Key"):
            return True

        # Skip for Bearer token authentication (JWT)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return True

        # Skip for non-browser User-Agents (basic check)
        user_agent = request.headers.get("User-Agent", "").lower()
        browser_indicators = ["mozilla", "webkit", "chrome", "safari", "firefox", "edge"]
        if not any(indicator in user_agent for indicator in browser_indicators):
            return True

        return False

    def _validate_csrf_token(self, request: Request) -> bool:
        """Validate CSRF token from header and cookie."""

        # Get CSRF token from header
        header_token = request.headers.get(settings.CSRF_HEADER_NAME)
        if not header_token:
            return False

        # Get CSRF token from cookie
        cookie_token = request.cookies.get(settings.CSRF_COOKIE_NAME)
        if not cookie_token:
            return False

        # Compare tokens in constant time
        return constant_time_compare(header_token, cookie_token)

    def _set_csrf_cookie(self, response: Response) -> None:
        """Set CSRF token cookie."""

        # Generate new CSRF token
        csrf_token = generate_csrf_token()

        # Set cookie
        response.set_cookie(
            key=settings.CSRF_COOKIE_NAME,
            value=csrf_token,
            max_age=settings.CSRF_TOKEN_EXPIRE_MINUTES * 60,
            httponly=False,  # JavaScript needs access to read this
            secure=settings.SESSION_COOKIE_SECURE,
            samesite=settings.SESSION_COOKIE_SAMESITE,
        )
