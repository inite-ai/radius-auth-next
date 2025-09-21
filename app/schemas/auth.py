"""Authentication schemas."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from .common import BaseResponse


class LoginRequest(BaseModel):
    """Login request schema."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")
    remember_me: bool = Field(default=False, description="Keep user logged in")


class LoginResponse(BaseResponse):
    """Login response schema."""

    user: "UserProfile"
    tokens: Optional["TokenResponse"] = None  # Optional for browser clients
    device_info: dict | None = None  # Device information for mobile clients


class TokenResponse(BaseModel):
    """Token response schema."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""

    refresh_token: str = Field(..., description="Refresh token")
    organization_id: int | None = Field(None, description="Organization context")


class RefreshTokenResponse(BaseResponse):
    """Refresh token response schema."""

    tokens: TokenResponse


class PasswordResetRequest(BaseModel):
    """Password reset request schema."""

    email: EmailStr = Field(..., description="Email address for reset")


class PasswordResetConfirmRequest(BaseModel):
    """Password reset confirmation schema."""

    token: str = Field(..., description="Reset token")
    new_password: str = Field(..., min_length=8, description="New password")


class UserProfile(BaseModel):
    """User profile schema for auth responses."""

    id: int
    email: str
    first_name: str
    last_name: str
    full_name: str
    is_verified: bool
    is_superuser: bool
    created_at: datetime
    last_login_at: datetime | None

    class Config:
        from_attributes = True


class APIKeyCreateRequest(BaseModel):
    """Request model for API key creation."""

    name: str = Field(..., description="API key name")
    scopes: list[str] | None = Field(None, description="API key scopes")
    expires_days: int | None = Field(None, ge=1, le=365, description="Expiration in days")


class APIKeyResponse(BaseModel):
    """Response model for API key."""

    id: int
    name: str
    prefix: str
    scopes: list[str]
    is_valid: bool
    last_used_at: datetime | None
    usage_count: int
    expires_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


class APIKeyCreateResponse(BaseResponse):
    """Response model for API key creation."""

    api_key: str
    key_info: APIKeyResponse
    warning: str


class APIKeyListResponse(BaseResponse):
    """Response model for API key list."""

    api_keys: list[APIKeyResponse]


class LogoutResponse(BaseResponse):
    """Response model for logout."""

    revoked_sessions: int | None = None


class VerifyTokenResponse(BaseResponse):
    """Response model for token verification."""

    user_id: int
