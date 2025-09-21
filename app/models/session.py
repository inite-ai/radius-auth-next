"""Session model for user session management."""

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.config.settings import settings

from .base import Base, TimestampMixin


class Session(Base, TimestampMixin):
    """Session model for tracking user sessions and refresh tokens."""
    
    __tablename__ = "sessions"
    
    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    
    # Foreign keys
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # Session data
    session_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    
    # Expiration
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    
    # Device/client info
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))  # IPv6 support
    device_name: Mapped[Optional[str]] = mapped_column(String(255))
    device_type: Mapped[Optional[str]] = mapped_column(String(50))  # web, mobile, api, etc.
    
    # Activity tracking
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # Security flags
    is_remember_me: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="sessions")
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if session is valid (active, not revoked, not expired)."""
        return self.is_active and not self.is_revoked and not self.is_expired
    
    @property
    def expires_in_seconds(self) -> int:
        """Get seconds until expiration."""
        if self.is_expired:
            return 0
        return int((self.expires_at - datetime.utcnow()).total_seconds())
    
    def extend_expiration(self, days: Optional[int] = None) -> None:
        """Extend session expiration."""
        days = days or settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        self.expires_at = datetime.utcnow() + timedelta(days=days)
    
    def revoke(self) -> None:
        """Revoke the session."""
        self.is_revoked = True
        self.is_active = False
    
    def update_activity(self, ip_address: Optional[str] = None) -> None:
        """Update last seen activity."""
        self.last_seen_at = datetime.utcnow()
        if ip_address:
            self.ip_address = ip_address
    
    def __repr__(self) -> str:
        return f"<Session(id={self.id}, user_id={self.user_id}, active={self.is_active}, expires={self.expires_at})>"
