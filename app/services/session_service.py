"""Session management service."""

from datetime import datetime, timedelta

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config.settings import settings
from app.models.session import Session
from app.models.user import User
from app.utils.security import generate_session_id, hash_token


class SessionService:
    """Service for managing user sessions."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_session(
        self,
        user: User,
        refresh_token: str,
        user_agent: str | None = None,
        ip_address: str | None = None,
        device_name: str | None = None,
        device_type: str | None = None,
        is_remember_me: bool = False,
    ) -> Session:
        """Create a new user session."""

        session_id = generate_session_id()
        refresh_token_hash = hash_token(refresh_token)

        # Calculate expiration
        if is_remember_me:
            expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        else:
            expire_days = 1  # Short session for non-remember-me

        expires_at = datetime.utcnow() + timedelta(days=expire_days)

        session = Session(
            user_id=user.id,
            session_id=session_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
            device_name=device_name,
            device_type=device_type,
            is_remember_me=is_remember_me,
        )

        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)

        return session

    # Removed: old get_session_by_id method - see line 91 for new implementation with primary key

    async def get_session_by_refresh_token(self, refresh_token: str) -> Session | None:
        """Get session by refresh token."""
        refresh_token_hash = hash_token(refresh_token)

        result = await self.db.execute(
            select(Session)
            .options(selectinload(Session.user))
            .where(
                and_(
                    Session.refresh_token_hash == refresh_token_hash,
                    Session.is_active,
                    not Session.is_revoked,
                )
            )
        )
        session = result.scalar_one_or_none()
        return session

    async def get_session_by_id(self, session_id: int, user_id: int) -> Session | None:
        """Get active session by id (primary key) and user_id."""
        result = await self.db.execute(
            select(Session)
            .options(selectinload(Session.user))
            .where(
                and_(
                    Session.id == session_id,
                    Session.user_id == user_id,
                    Session.is_active,
                    not Session.is_revoked,
                )
            )
        )
        session = result.scalar_one_or_none()
        return session

    async def validate_session(self, session: Session) -> bool:
        """Validate if session is still valid."""
        if not session.is_valid:
            return False

        # Check if user is still active
        if not session.user.can_login:
            await self.revoke_session(session)
            return False

        return True

    async def update_session_activity(
        self,
        session: Session,
        ip_address: str | None = None,
    ) -> None:
        """Update session last activity."""
        session.update_activity(ip_address)
        await self.db.commit()

    async def refresh_session(
        self,
        session: Session,
        new_refresh_token: str,
    ) -> Session:
        """Refresh session with new token (implements refresh rotation)."""

        # Revoke old session
        await self.revoke_session(session)

        # Create new session with new refresh token
        new_session = await self.create_session(
            user=session.user,
            refresh_token=new_refresh_token,
            user_agent=session.user_agent,
            ip_address=session.ip_address,
            device_name=session.device_name,
            device_type=session.device_type,
            is_remember_me=session.is_remember_me,
        )

        return new_session

    # Removed: old revoke_session method - see line 273 for new implementation
    # Removed: old revoke_all_user_sessions method - see line 279 for new implementation

    async def revoke_other_sessions(self, user_id: int, current_session_id: str) -> int:
        """Revoke all sessions for user except current one."""
        result = await self.db.execute(
            select(Session).where(
                and_(
                    Session.user_id == user_id,
                    Session.session_id != current_session_id,
                    Session.is_active,
                    not Session.is_revoked,
                )
            )
        )
        sessions = result.scalars().all()

        for session in sessions:
            session.revoke()

        await self.db.commit()
        return len(sessions)

    async def get_user_sessions(
        self,
        user_id: int,
        include_revoked: bool = False,
    ) -> list[Session]:
        """Get all sessions for a user."""
        query = select(Session).where(Session.user_id == user_id)

        if not include_revoked:
            query = query.where(
                and_(
                    Session.is_active,
                    not Session.is_revoked,
                )
            )

        query = query.order_by(Session.last_seen_at.desc())

        result = await self.db.execute(query)
        return result.scalars().all()

    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions. Returns number of cleaned sessions."""
        now = datetime.utcnow()

        result = await self.db.execute(select(Session).where(Session.expires_at < now))
        expired_sessions = result.scalars().all()

        for session in expired_sessions:
            session.revoke()

        await self.db.commit()
        return len(expired_sessions)

    async def get_session_stats(self, user_id: int) -> dict:
        """Get session statistics for a user."""
        # Active sessions
        active_result = await self.db.execute(
            select(Session).where(
                and_(
                    Session.user_id == user_id,
                    Session.is_active,
                    not Session.is_revoked,
                    Session.expires_at > datetime.utcnow(),
                )
            )
        )
        active_sessions = active_result.scalars().all()

        # Total sessions (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        total_result = await self.db.execute(
            select(Session).where(
                and_(
                    Session.user_id == user_id,
                    Session.created_at > thirty_days_ago,
                )
            )
        )
        total_sessions = total_result.scalars().all()

        # Group by device type
        device_types = {}
        for session in active_sessions:
            device_type = session.device_type or "unknown"
            device_types[device_type] = device_types.get(device_type, 0) + 1

        return {
            "active_sessions": len(active_sessions),
            "total_sessions_30d": len(total_sessions),
            "device_types": device_types,
            "last_activity": max(
                (s.last_seen_at for s in active_sessions),
                default=None,
            ),
        }

    async def revoke_session(self, session: Session) -> None:
        """Revoke a session by marking it as inactive and revoked."""
        session.is_active = False
        session.is_revoked = True
        await self.db.commit()

    async def revoke_all_user_sessions(self, user_id: int) -> int:
        """Revoke all sessions for a user."""
        result = await self.db.execute(
            update(Session)
            .where(Session.user_id == user_id)
            .values(is_active=False, is_revoked=True)
        )
        await self.db.commit()
        return result.rowcount
