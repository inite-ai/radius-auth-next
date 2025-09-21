"""Custom exceptions for the application."""

from typing import Any, Dict, Optional


class BaseAuthException(Exception):
    """Base exception for authentication/authorization errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(BaseAuthException):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, error_code="AUTHENTICATION_FAILED", **kwargs)


class AuthorizationError(BaseAuthException):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Access denied", **kwargs):
        super().__init__(message, error_code="ACCESS_DENIED", **kwargs)


class ValidationError(BaseAuthException):
    """Raised when validation fails."""
    
    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)


class NotFoundError(BaseAuthException):
    """Raised when a resource is not found."""
    
    def __init__(self, message: str = "Resource not found", **kwargs):
        super().__init__(message, error_code="NOT_FOUND", **kwargs)


class ConflictError(BaseAuthException):
    """Raised when there's a conflict (e.g., duplicate resource)."""
    
    def __init__(self, message: str = "Resource conflict", **kwargs):
        super().__init__(message, error_code="CONFLICT", **kwargs)


class TokenExpiredError(AuthenticationError):
    """Raised when a token has expired."""
    
    def __init__(self, message: str = "Token has expired", **kwargs):
        super().__init__(message, error_code="TOKEN_EXPIRED", **kwargs)


class InvalidTokenError(AuthenticationError):
    """Raised when a token is invalid."""
    
    def __init__(self, message: str = "Invalid token", **kwargs):
        super().__init__(message, error_code="INVALID_TOKEN", **kwargs)


class AccountLockedError(AuthenticationError):
    """Raised when account is locked."""
    
    def __init__(self, message: str = "Account is locked", **kwargs):
        super().__init__(message, error_code="ACCOUNT_LOCKED", **kwargs)


class InsufficientPermissionsError(AuthorizationError):
    """Raised when user doesn't have sufficient permissions."""
    
    def __init__(self, message: str = "Insufficient permissions", **kwargs):
        super().__init__(message, error_code="INSUFFICIENT_PERMISSIONS", **kwargs)


class OrganizationNotFoundError(NotFoundError):
    """Raised when organization is not found."""
    
    def __init__(self, message: str = "Organization not found", **kwargs):
        super().__init__(message, error_code="ORGANIZATION_NOT_FOUND", **kwargs)


class UserNotFoundError(NotFoundError):
    """Raised when user is not found."""
    
    def __init__(self, message: str = "User not found", **kwargs):
        super().__init__(message, error_code="USER_NOT_FOUND", **kwargs)


class EmailAlreadyExistsError(ConflictError):
    """Raised when email already exists."""
    
    def __init__(self, message: str = "Email already exists", **kwargs):
        super().__init__(message, error_code="EMAIL_EXISTS", **kwargs)


class UsernameAlreadyExistsError(ConflictError):
    """Raised when username already exists."""
    
    def __init__(self, message: str = "Username already exists", **kwargs):
        super().__init__(message, error_code="USERNAME_EXISTS", **kwargs)
