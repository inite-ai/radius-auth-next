"""User schemas."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, validator

from .common import BaseResponse, TimestampMixin
from app.utils.validators import validate_email, validate_password, validate_phone_number, validate_timezone, validate_locale


class UserCreate(BaseModel):
    """Schema for creating a new user."""
    
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")
    first_name: str = Field(..., min_length=1, max_length=100, description="First name")
    last_name: str = Field(..., min_length=1, max_length=100, description="Last name")
    middle_name: Optional[str] = Field(None, max_length=100, description="Middle name")
    username: Optional[str] = Field(None, min_length=3, max_length=30, description="Username")
    phone: Optional[str] = Field(None, description="Phone number")
    timezone: Optional[str] = Field(None, description="User timezone")
    locale: Optional[str] = Field(None, description="User locale")
    bio: Optional[str] = Field(None, max_length=1000, description="User biography")
    
    @validator("email")
    def validate_email_format(cls, v):
        return validate_email(v)
    
    @validator("password")
    def validate_password_strength(cls, v):
        validate_password(v)
        return v
    
    @validator("phone")
    def validate_phone_format(cls, v):
        if v:
            validate_phone_number(v)
        return v
    
    @validator("timezone")
    def validate_timezone_format(cls, v):
        if v:
            validate_timezone(v)
        return v
    
    @validator("locale")
    def validate_locale_format(cls, v):
        if v:
            validate_locale(v)
        return v


class UserUpdate(BaseModel):
    """Schema for updating user information."""
    
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    middle_name: Optional[str] = Field(None, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=30)
    phone: Optional[str] = Field(None)
    avatar_url: Optional[str] = Field(None, max_length=500)
    timezone: Optional[str] = Field(None)
    locale: Optional[str] = Field(None)
    bio: Optional[str] = Field(None, max_length=1000)
    
    @validator("phone")
    def validate_phone_format(cls, v):
        if v:
            validate_phone_number(v)
        return v
    
    @validator("timezone")
    def validate_timezone_format(cls, v):
        if v:
            validate_timezone(v)
        return v
    
    @validator("locale")
    def validate_locale_format(cls, v):
        if v:
            validate_locale(v)
        return v


class UserResponse(TimestampMixin):
    """Schema for user response."""
    
    id: int
    email: str
    username: Optional[str]
    first_name: str
    last_name: str
    middle_name: Optional[str]
    phone: Optional[str]
    avatar_url: Optional[str]
    timezone: Optional[str]
    locale: Optional[str]
    bio: Optional[str]
    is_verified: bool
    is_active: bool
    last_login_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class UserProfile(BaseModel):
    """Schema for user profile (minimal info)."""
    
    id: int
    email: str
    username: Optional[str]
    first_name: str
    last_name: str
    full_name: str
    avatar_url: Optional[str]
    is_verified: bool
    is_superuser: bool
    
    class Config:
        from_attributes = True


class UserSecurity(BaseModel):
    """Schema for user security information."""
    
    id: int
    email: str
    is_active: bool
    is_verified: bool
    failed_login_attempts: int
    is_locked: bool
    locked_until: Optional[datetime]
    last_login_at: Optional[datetime]
    password_changed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class UserListResponse(BaseResponse):
    """Schema for user list response."""
    
    users: List[UserResponse]
    total: int
    page: int
    per_page: int


class UserDetailResponse(BaseResponse):
    """Schema for user detail response."""
    
    user: UserResponse


class PasswordChangeRequest(BaseModel):
    """Schema for password change."""
    
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")
    
    @validator("new_password")
    def validate_password_strength(cls, v):
        validate_password(v)
        return v


class EmailVerificationRequest(BaseModel):
    """Schema for email verification."""
    
    token: str = Field(..., description="Verification token")


class UserInviteRequest(BaseModel):
    """Schema for inviting user to organization."""
    
    email: EmailStr = Field(..., description="Email to invite")
    role: str = Field(..., description="Role to assign")
    organization_id: int = Field(..., description="Organization ID")
    
    @validator("role")
    def validate_role(cls, v):
        from app.models.membership import Role
        if v not in [role.value for role in Role]:
            raise ValueError(f"Invalid role. Must be one of: {[role.value for role in Role]}")
        return v
