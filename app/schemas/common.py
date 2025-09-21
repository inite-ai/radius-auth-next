"""Common Pydantic schemas."""

from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class BaseResponse(BaseModel):
    """Base response model."""
    
    success: bool = True
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseResponse):
    """Error response model."""
    
    success: bool = False
    error_code: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None


class SuccessResponse(BaseResponse, Generic[T]):
    """Success response model with data."""
    
    data: T


class PaginatedResponse(BaseResponse, Generic[T]):
    """Paginated response model."""
    
    data: List[T]
    pagination: "PaginationMeta"


class PaginationMeta(BaseModel):
    """Pagination metadata."""
    
    page: int = Field(ge=1, description="Current page number")
    per_page: int = Field(ge=1, le=100, description="Items per page")
    total: int = Field(ge=0, description="Total number of items")
    pages: int = Field(ge=0, description="Total number of pages")
    has_next: bool = Field(description="Whether there is a next page")
    has_prev: bool = Field(description="Whether there is a previous page")


class PaginationParams(BaseModel):
    """Pagination parameters for requests."""
    
    page: int = Field(default=1, ge=1, description="Page number")
    per_page: int = Field(default=20, ge=1, le=100, description="Items per page")


class SearchParams(BaseModel):
    """Search parameters."""
    
    query: Optional[str] = Field(None, max_length=100, description="Search query")
    sort_by: Optional[str] = Field(None, description="Field to sort by")
    sort_order: Optional[str] = Field(
        default="asc",
        pattern="^(asc|desc)$",
        description="Sort order: asc or desc"
    )


class TimestampMixin(BaseModel):
    """Mixin for timestamp fields."""
    
    created_at: datetime
    updated_at: datetime
