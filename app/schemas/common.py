"""Common Pydantic schemas."""

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class BaseResponse(BaseModel):
    """Base response model."""

    model_config = {"extra": "allow"}

    success: bool = True
    message: str | None = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class ErrorResponse(BaseResponse):
    """Error response model."""

    success: bool = False
    error_code: str | None = None
    error_details: dict[str, Any] | None = None


class SuccessResponse(BaseResponse, Generic[T]):
    """Success response model with data."""

    data: T


class PaginatedResponse(BaseResponse, Generic[T]):
    """Paginated response model."""

    data: list[T]
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

    query: str | None = Field(None, max_length=100, description="Search query")
    sort_by: str | None = Field(None, description="Field to sort by")
    sort_order: str | None = Field(
        default="asc", pattern="^(asc|desc)$", description="Sort order: asc or desc"
    )


class TimestampMixin(BaseModel):
    """Mixin for timestamp fields."""

    created_at: datetime
    updated_at: datetime
