"""Global exception handler middleware."""

import logging
from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from app.utils.exceptions import (
    AccountLockedError,
    AuthenticationError,
    AuthorizationError,
    BaseAuthException,
    ConflictError,
    EmailAlreadyExistsError,
    InsufficientPermissionsError,
    InvalidTokenError,
    NotFoundError,
    OrganizationNotFoundError,
    TokenExpiredError,
    UsernameAlreadyExistsError,
    UserNotFoundError,
    ValidationError,
)

logger = logging.getLogger(__name__)


class ExceptionHandlers:
    """Centralized exception handlers for the application."""

    @staticmethod
    async def base_auth_exception_handler(request: Request, exc: BaseAuthException) -> JSONResponse:
        """Handle all custom auth exceptions."""

        logger.warning(
            f"Auth exception in {request.method} {request.url}: {exc.message}",
            extra={
                "error_code": exc.error_code,
                "details": exc.details,
                "path": str(request.url.path),
                "method": request.method,
            },
        )

        # Map exception types to HTTP status codes
        status_mapping = {
            # Authentication errors -> 401
            AuthenticationError: status.HTTP_401_UNAUTHORIZED,
            TokenExpiredError: status.HTTP_401_UNAUTHORIZED,
            InvalidTokenError: status.HTTP_401_UNAUTHORIZED,
            AccountLockedError: status.HTTP_423_LOCKED,
            # Authorization errors -> 403
            AuthorizationError: status.HTTP_403_FORBIDDEN,
            InsufficientPermissionsError: status.HTTP_403_FORBIDDEN,
            # Not found errors -> 404
            NotFoundError: status.HTTP_404_NOT_FOUND,
            UserNotFoundError: status.HTTP_404_NOT_FOUND,
            OrganizationNotFoundError: status.HTTP_404_NOT_FOUND,
            # Conflict errors -> 409
            ConflictError: status.HTTP_409_CONFLICT,
            EmailAlreadyExistsError: status.HTTP_409_CONFLICT,
            UsernameAlreadyExistsError: status.HTTP_409_CONFLICT,
            # Validation errors -> 400
            ValidationError: status.HTTP_400_BAD_REQUEST,
        }

        status_code = status_mapping.get(type(exc), status.HTTP_500_INTERNAL_SERVER_ERROR)

        return JSONResponse(
            status_code=status_code,
            content={
                "success": False,
                "message": exc.message,
                "error_code": exc.error_code,
                "details": exc.details,
            },
        )

    @staticmethod
    async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle validation exceptions from pydantic."""

        logger.warning(
            f"Validation error in {request.method} {request.url}: {str(exc)}",
            extra={
                "path": str(request.url.path),
                "method": request.method,
                "exception_type": type(exc).__name__,
            },
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "message": "Validation failed",
                "error_code": "VALIDATION_ERROR",
                "details": {"validation_errors": str(exc)},
            },
        )

    @staticmethod
    async def integrity_error_handler(request: Request, exc: IntegrityError) -> JSONResponse:
        """Handle database integrity errors."""

        logger.error(
            f"Database integrity error in {request.method} {request.url}: {str(exc)}",
            extra={
                "path": str(request.url.path),
                "method": request.method,
            },
        )

        # Parse common integrity violations
        error_message = "Database constraint violation"
        error_code = "INTEGRITY_ERROR"

        if "duplicate key" in str(exc).lower():
            error_message = "Resource already exists"
            error_code = "DUPLICATE_RESOURCE"
        elif "foreign key" in str(exc).lower():
            error_message = "Referenced resource not found"
            error_code = "FOREIGN_KEY_VIOLATION"
        elif "not null" in str(exc).lower():
            error_message = "Required field is missing"
            error_code = "REQUIRED_FIELD_MISSING"

        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "success": False,
                "message": error_message,
                "error_code": error_code,
                "details": {},
            },
        )

    @staticmethod
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Handle FastAPI HTTP exceptions with consistent format."""

        logger.warning(
            f"HTTP exception in {request.method} {request.url}: {exc.detail}",
            extra={
                "status_code": exc.status_code,
                "path": str(request.url.path),
                "method": request.method,
            },
        )

        # Map status codes to error codes
        error_code_mapping = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            422: "VALIDATION_ERROR",
            429: "RATE_LIMITED",
            500: "INTERNAL_ERROR",
        }

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "message": exc.detail,
                "error_code": error_code_mapping.get(exc.status_code, "HTTP_ERROR"),
                "details": {},
            },
        )

    @staticmethod
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions."""

        logger.error(
            f"Unexpected error in {request.method} {request.url}: {str(exc)}",
            extra={
                "path": str(request.url.path),
                "method": request.method,
                "exception_type": type(exc).__name__,
            },
            exc_info=True,
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "Internal server error",
                "error_code": "INTERNAL_ERROR",
                "details": {},
            },
        )


def register_exception_handlers(app: Any) -> None:
    """Register all exception handlers with the FastAPI app."""

    handlers = ExceptionHandlers()

    # Custom auth exceptions
    app.add_exception_handler(BaseAuthException, handlers.base_auth_exception_handler)

    # Database errors
    app.add_exception_handler(IntegrityError, handlers.integrity_error_handler)

    # HTTP exceptions
    app.add_exception_handler(HTTPException, handlers.http_exception_handler)

    # Pydantic validation errors
    from pydantic import ValidationError as PydanticValidationError

    app.add_exception_handler(PydanticValidationError, handlers.validation_exception_handler)

    # Catch-all for unexpected errors
    app.add_exception_handler(Exception, handlers.general_exception_handler)
