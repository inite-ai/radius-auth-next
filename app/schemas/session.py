"""Session schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from .common import BaseResponse


class SessionResponse(BaseModel):
    """Schema for session response."""

    id: int
    session_id: str
    device_name: str | None
    device_type: str | None
    user_agent: str | None
    ip_address: str | None
    is_current: bool = Field(default=False, description="Whether this is the current session")
    is_active: bool
    is_revoked: bool
    is_remember_me: bool
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True


class SessionListResponse(BaseResponse):
    """Schema for session list response."""

    sessions: list[SessionResponse]
    total: int


class SessionStatsResponse(BaseResponse):
    """Schema for session statistics response."""

    stats: "SessionStats"


class SessionStats(BaseModel):
    """Schema for session statistics."""

    active_sessions: int = Field(description="Number of active sessions")
    total_sessions_30d: int = Field(description="Total sessions in last 30 days")
    device_types: dict[str, int] = Field(description="Sessions grouped by device type")
    last_activity: datetime | None = Field(description="Last activity timestamp")


class RevokeOtherSessionsRequest(BaseModel):
    """Schema for revoking other sessions."""

    current_session_id: str = Field(..., description="Current session ID to keep active")
