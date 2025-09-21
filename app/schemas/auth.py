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


class TokenResponse(BaseModel):
    """Token response schema."""
    
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration in seconds")


class RefreshTokenRequest(BaseModel):
    """Refresh token request schema."""
    
    refresh_token: str = Field(..., description="Refresh token")
    organization_id: Optional[int] = Field(None, description="Organization context")


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
    last_login_at: Optional[datetime]
    
    class Config:
        from_attributes = True
