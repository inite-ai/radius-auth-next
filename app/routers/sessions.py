"""Session management routes."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.constants.status_codes import APIStatus
from app.decorators.permissions import require_delete_permission, require_read_permission
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_session_service
from app.models.user import User
from app.schemas.session import (
    RevokeOtherSessionsRequest,
    SessionListResponse,
    SessionResponse,
    SessionStats,
    SessionStatsResponse,
)
from app.services.session_service import SessionService
from app.utils.response_builders import ResponseBuilder

router = APIRouter()


@router.get("/", response_model=SessionListResponse)
@require_read_permission("session")
async def get_user_sessions(
    current_user: User = Depends(get_current_active_user),
    session_service: SessionService = Depends(get_session_service),
    include_revoked: bool = Query(False, description="Include revoked sessions"),
):
    """Get current user's sessions."""
    sessions = await session_service.get_user_sessions(
        user_id=current_user.id,
        include_revoked=include_revoked,
    )

    # TODO: Detect current session by comparing with request session
    session_responses = []
    for session in sessions:
        session_response = SessionResponse(
            id=session.id,
            session_id=session.session_id,
            device_name=session.device_name,
            device_type=session.device_type,
            user_agent=session.user_agent,
            ip_address=session.ip_address,
            is_current=False,  # TODO: implement current session detection
            is_active=session.is_active,
            is_revoked=session.is_revoked,
            is_remember_me=session.is_remember_me,
            created_at=session.created_at,
            last_seen_at=session.last_seen_at,
            expires_at=session.expires_at,
        )
        session_responses.append(session_response)

    return SessionListResponse(
        success=True,
        message="Sessions retrieved successfully",
        sessions=session_responses,
        total=len(session_responses),
    )


@router.delete("/other")
@require_delete_permission("session")
async def revoke_other_sessions(
    revoke_request: RevokeOtherSessionsRequest,
    current_user: User = Depends(get_current_active_user),
    session_service: SessionService = Depends(get_session_service),
):
    """Revoke all other sessions except current one."""
    revoked_count = await session_service.revoke_other_sessions(
        user_id=current_user.id,
        current_session_id=revoke_request.current_session_id,
    )

    return ResponseBuilder.sessions_revoked(revoked_count)


@router.delete("/{session_id}")
@require_delete_permission("session")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user),
    session_service: SessionService = Depends(get_session_service),
):
    """Revoke a specific session."""
    session = await session_service.get_session_by_session_id(session_id)

    if not session:
        raise HTTPException(
            status_code=APIStatus.NOT_FOUND,
            detail="Session not found",
        )

    # Check if session belongs to current user
    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=APIStatus.FORBIDDEN,
            detail="Access denied",
        )

    await session_service.revoke_session(session)

    return ResponseBuilder.session_revoked()


@router.get("/stats", response_model=SessionStatsResponse)
@require_read_permission("session")
async def get_session_stats(
    current_user: User = Depends(get_current_active_user),
    session_service: SessionService = Depends(get_session_service),
):
    """Get session statistics for current user."""
    stats_data = await session_service.get_session_stats(current_user.id)

    return SessionStatsResponse(
        success=True,
        message="Session statistics retrieved successfully",
        stats=SessionStats(**stats_data),
    )
