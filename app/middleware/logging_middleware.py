"""Request/Response logging middleware."""

import json
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging all API requests and responses."""

    def __init__(
        self,
        app: Any,
        log_body: bool = False,
        log_headers: bool = False,
        sensitive_headers: set[str] | None = None,
        exclude_paths: set[str] | None = None,
        max_body_size: int = 1024,
    ):
        """
        Initialize request logging middleware.

        Args:
            app: ASGI application
            log_body: Whether to log request/response bodies
            log_headers: Whether to log headers
            sensitive_headers: Headers to exclude from logging
            exclude_paths: Paths to exclude from logging (e.g., health checks)
            max_body_size: Maximum body size to log in bytes
        """
        super().__init__(app)
        self.log_body = log_body
        self.log_headers = log_headers
        self.sensitive_headers = sensitive_headers or {
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "authentication",
        }
        self.exclude_paths = exclude_paths or {
            "/health",
            "/metrics",
            "/favicon.ico",
            "/docs",
            "/redoc",
            "/openapi.json",
        }
        self.max_body_size = max_body_size

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and response logging."""

        # Skip logging for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Generate request ID for tracing
        request_id = str(uuid.uuid4())

        # Start timing
        start_time = time.time()

        # Log request
        await self._log_request(request, request_id)

        # Store request ID in request state
        request.state.request_id = request_id

        try:
            # Process request
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Log response
            await self._log_response(request, response, request_id, process_time)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Process-Time"] = f"{process_time:.4f}"

            return response

        except Exception as e:
            # Log error
            process_time = time.time() - start_time
            await self._log_error(request, e, request_id, process_time)
            raise

    async def _log_request(self, request: Request, request_id: str):
        """Log incoming request."""

        # Basic request info
        log_data = {
            "event": "request_started",
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent"),
        }

        # Add headers if enabled
        if self.log_headers:
            log_data["headers"] = self._filter_headers(dict(request.headers))

        # Add body if enabled
        if self.log_body and request.method in ("POST", "PUT", "PATCH"):
            body = await self._get_request_body(request)
            if body:
                log_data["body"] = body

        logger.info("API Request", extra=log_data)

    async def _log_response(
        self, request: Request, response: Response, request_id: str, process_time: float
    ):
        """Log outgoing response."""

        log_data = {
            "event": "request_completed",
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "process_time": f"{process_time:.4f}s",
            "response_size": len(response.body) if hasattr(response, "body") else 0,
        }

        # Add response headers if enabled
        if self.log_headers:
            log_data["response_headers"] = self._filter_headers(dict(response.headers))

        # Add response body if enabled and not too large
        if self.log_body and hasattr(response, "body"):
            body = self._get_response_body(response)
            if body:
                log_data["response_body"] = body

        # Determine log level based on status code
        if response.status_code >= 500:
            logger.error("API Response", extra=log_data)
        elif response.status_code >= 400:
            logger.warning("API Response", extra=log_data)
        else:
            logger.info("API Response", extra=log_data)

    async def _log_error(
        self, request: Request, error: Exception, request_id: str, process_time: float
    ):
        """Log request error."""

        log_data = {
            "event": "request_failed",
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "process_time": f"{process_time:.4f}s",
        }

        logger.error("API Request Failed", extra=log_data, exc_info=True)

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""

        # Check for forwarded headers (behind proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        forwarded = request.headers.get("x-forwarded")
        if forwarded:
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        # Fall back to direct client
        if hasattr(request, "client") and request.client:
            return request.client.host

        return "unknown"

    def _filter_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Filter sensitive headers from logging."""

        filtered = {}
        for key, value in headers.items():
            if key.lower() in self.sensitive_headers:
                filtered[key] = "[REDACTED]"
            else:
                filtered[key] = value

        return filtered

    async def _get_request_body(self, request: Request) -> str | None:
        """Get request body for logging."""

        try:
            # Get body
            body = await request.body()

            if not body:
                return None

            # Check size limit
            if len(body) > self.max_body_size:
                return f"[BODY TOO LARGE: {len(body)} bytes]"

            # Try to decode as text
            try:
                body_str = body.decode("utf-8")

                # Try to parse as JSON for pretty formatting
                try:
                    parsed = json.loads(body_str)
                    return json.dumps(parsed, indent=2)
                except json.JSONDecodeError:
                    return body_str

            except UnicodeDecodeError:
                return f"[BINARY BODY: {len(body)} bytes]"

        except Exception as e:
            logger.warning(f"Failed to read request body: {e}")
            return "[BODY READ ERROR]"

    def _get_response_body(self, response: Response) -> str | None:
        """Get response body for logging."""

        try:
            if not hasattr(response, "body") or not response.body:
                return None

            body = response.body

            # Check size limit
            if len(body) > self.max_body_size:
                return f"[BODY TOO LARGE: {len(body)} bytes]"

            # Try to decode as text
            try:
                body_str = body.decode("utf-8")

                # Try to parse as JSON for pretty formatting
                try:
                    parsed = json.loads(body_str)
                    return json.dumps(parsed, indent=2)
                except json.JSONDecodeError:
                    return body_str

            except UnicodeDecodeError:
                return f"[BINARY BODY: {len(body)} bytes]"

        except Exception as e:
            logger.warning(f"Failed to read response body: {e}")
            return "[BODY READ ERROR]"


# Performance monitoring middleware
class PerformanceMiddleware(BaseHTTPMiddleware):
    """Middleware for performance monitoring."""

    def __init__(
        self,
        app: Any,
        slow_request_threshold: float = 1.0,
        enable_metrics: bool = True,
    ):
        """
        Initialize performance middleware.

        Args:
            app: ASGI application
            slow_request_threshold: Threshold for slow request logging (seconds)
            enable_metrics: Whether to collect performance metrics
        """
        super().__init__(app)
        self.slow_threshold = slow_request_threshold
        self.enable_metrics = enable_metrics
        self.request_metrics = {}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Monitor request performance."""

        start_time = time.time()

        try:
            response = await call_next(request)
            process_time = time.time() - start_time

            # Log slow requests
            if process_time > self.slow_threshold:
                logger.warning(
                    f"Slow request detected: {request.method} {request.url.path}",
                    extra={
                        "event": "slow_request",
                        "method": request.method,
                        "path": request.url.path,
                        "process_time": f"{process_time:.4f}s",
                        "threshold": f"{self.slow_threshold}s",
                        "status_code": response.status_code,
                    },
                )

            # Collect metrics if enabled
            if self.enable_metrics:
                self._update_metrics(request.method, request.url.path, process_time)

            return response

        except Exception as e:
            process_time = time.time() - start_time
            logger.error(
                f"Request failed: {request.method} {request.url.path}",
                extra={
                    "event": "request_error",
                    "method": request.method,
                    "path": request.url.path,
                    "process_time": f"{process_time:.4f}s",
                    "error": str(e),
                },
                exc_info=True,
            )
            raise

    def _update_metrics(self, method: str, path: str, process_time: float):
        """Update performance metrics."""

        key = f"{method}:{path}"

        if key not in self.request_metrics:
            self.request_metrics[key] = {
                "count": 0,
                "total_time": 0.0,
                "min_time": float("inf"),
                "max_time": 0.0,
            }

        metrics = self.request_metrics[key]
        metrics["count"] += 1
        metrics["total_time"] += process_time
        metrics["min_time"] = min(metrics["min_time"], process_time)
        metrics["max_time"] = max(metrics["max_time"], process_time)

    def get_metrics(self) -> dict[str, Any]:
        """Get collected performance metrics."""

        result = {}
        for key, metrics in self.request_metrics.items():
            result[key] = {
                **metrics,
                "avg_time": metrics["total_time"] / metrics["count"] if metrics["count"] > 0 else 0,
            }

        return result
