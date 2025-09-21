"""HTTP status code constants with semantic names."""

from enum import IntEnum


class APIStatus(IntEnum):
    """Semantic HTTP status codes for API responses."""

    # Success
    SUCCESS = 200
    CREATED = 201
    NO_CONTENT = 204

    # Client errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    VALIDATION_ERROR = 422
    RATE_LIMITED = 429

    # Server errors
    INTERNAL_ERROR = 500
    SERVICE_UNAVAILABLE = 503


class AuthStatus(IntEnum):
    """Authentication and authorization specific status codes."""

    # Authentication
    INVALID_CREDENTIALS = 401
    TOKEN_EXPIRED = 401
    TOKEN_INVALID = 401
    MISSING_TOKEN = 401

    # Authorization
    ACCESS_DENIED = 403
    INSUFFICIENT_PERMISSIONS = 403
    ACCOUNT_LOCKED = 423

    # Account states
    ACCOUNT_DISABLED = 403
    EMAIL_NOT_VERIFIED = 403


class ValidationStatus(IntEnum):
    """Validation specific status codes."""

    INVALID_INPUT = 422
    MISSING_FIELD = 422
    INVALID_FORMAT = 422
    VALUE_TOO_LONG = 422
    VALUE_TOO_SHORT = 422
    INVALID_EMAIL = 422
    WEAK_PASSWORD = 422


class ResourceStatus(IntEnum):
    """Resource management status codes."""

    RESOURCE_CREATED = 201
    RESOURCE_UPDATED = 200
    RESOURCE_DELETED = 204
    RESOURCE_NOT_FOUND = 404
    RESOURCE_CONFLICT = 409
    DUPLICATE_RESOURCE = 409

    # Specific resources
    USER_NOT_FOUND = 404
    USER_EXISTS = 409
    ORGANIZATION_NOT_FOUND = 404
    ORGANIZATION_EXISTS = 409
    EMAIL_EXISTS = 409
    USERNAME_EXISTS = 409


# Convenience mappings for common scenarios
SUCCESS_CODES = {
    "get": APIStatus.SUCCESS,
    "post": APIStatus.CREATED,
    "put": APIStatus.SUCCESS,
    "patch": APIStatus.SUCCESS,
    "delete": APIStatus.NO_CONTENT,
}

ERROR_CODES = {
    "not_found": APIStatus.NOT_FOUND,
    "validation": APIStatus.VALIDATION_ERROR,
    "conflict": APIStatus.CONFLICT,
    "unauthorized": APIStatus.UNAUTHORIZED,
    "forbidden": APIStatus.FORBIDDEN,
}


def get_success_status(method: str) -> int:
    """Get appropriate success status for HTTP method."""
    return SUCCESS_CODES.get(method.lower(), APIStatus.SUCCESS)


def get_error_status(error_type: str) -> int:
    """Get appropriate error status for error type."""
    return ERROR_CODES.get(error_type.lower(), APIStatus.INTERNAL_ERROR)
