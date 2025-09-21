"""Organization schemas."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, validator

from .common import BaseResponse, TimestampMixin
from app.utils.validators import validate_organization_slug, validate_hex_color, validate_url, validate_email


class OrganizationCreate(BaseModel):
    """Schema for creating organization."""
    
    name: str = Field(..., min_length=1, max_length=255, description="Organization name")
    slug: str = Field(..., min_length=3, max_length=50, description="Organization slug")
    description: Optional[str] = Field(None, max_length=1000, description="Organization description")
    website: Optional[str] = Field(None, max_length=255, description="Website URL")
    email: Optional[EmailStr] = Field(None, description="Organization email")
    phone: Optional[str] = Field(None, max_length=20, description="Phone number")
    
    @validator("slug")
    def validate_slug_format(cls, v):
        validate_organization_slug(v)
        return v.lower()
    
    @validator("website")
    def validate_website_url(cls, v):
        if v:
            validate_url(v)
        return v


class OrganizationUpdate(BaseModel):
    """Schema for updating organization."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    website: Optional[str] = Field(None, max_length=255)
    email: Optional[EmailStr] = Field(None)
    phone: Optional[str] = Field(None, max_length=20)
    logo_url: Optional[str] = Field(None, max_length=500)
    primary_color: Optional[str] = Field(None, description="Hex color code")
    
    @validator("website")
    def validate_website_url(cls, v):
        if v:
            validate_url(v)
        return v
    
    @validator("primary_color")
    def validate_color_format(cls, v):
        if v:
            validate_hex_color(v)
        return v


class OrganizationResponse(TimestampMixin):
    """Schema for organization response."""
    
    id: int
    name: str
    slug: str
    description: Optional[str]
    is_active: bool
    is_personal: bool
    website: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    logo_url: Optional[str]
    primary_color: Optional[str]
    plan: str
    max_users: Optional[int]
    user_count: int
    
    class Config:
        from_attributes = True


class OrganizationSummary(BaseModel):
    """Schema for organization summary (list view)."""
    
    id: int
    name: str
    slug: str
    description: Optional[str]
    logo_url: Optional[str]
    is_personal: bool
    user_count: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class MembershipResponse(TimestampMixin):
    """Schema for membership response."""
    
    id: int
    user_id: int
    organization_id: int
    role: str
    is_active: bool
    user: "UserSummary"
    
    class Config:
        from_attributes = True


class UserSummary(BaseModel):
    """Schema for user summary in membership."""
    
    id: int
    email: str
    first_name: str
    last_name: str
    full_name: str
    avatar_url: Optional[str]
    last_login_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class OrganizationWithRole(BaseModel):
    """Schema for organization with user's role."""
    
    organization: OrganizationSummary
    role: str
    joined_at: datetime
    
    class Config:
        from_attributes = True


class OrganizationListResponse(BaseResponse):
    """Schema for organization list response."""
    
    organizations: List[OrganizationWithRole]
    total: int


class OrganizationDetailResponse(BaseResponse):
    """Schema for organization detail response."""
    
    organization: OrganizationResponse
    user_role: Optional[str]


class MemberListResponse(BaseResponse):
    """Schema for member list response."""
    
    members: List[MembershipResponse]
    total: int
    page: int
    per_page: int


class MemberInviteRequest(BaseModel):
    """Schema for inviting member to organization."""
    
    email: EmailStr = Field(..., description="Email to invite")
    role: str = Field(..., description="Role to assign")
    
    @validator("role")
    def validate_role(cls, v):
        from app.models.membership import Role
        if v not in [role.value for role in Role]:
            raise ValueError(f"Invalid role. Must be one of: {[role.value for role in Role]}")
        return v


class MemberRoleUpdateRequest(BaseModel):
    """Schema for updating member role."""
    
    role: str = Field(..., description="New role")
    
    @validator("role")
    def validate_role(cls, v):
        from app.models.membership import Role
        if v not in [role.value for role in Role]:
            raise ValueError(f"Invalid role. Must be one of: {[role.value for role in Role]}")
        return v
