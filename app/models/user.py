"""User model."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """User model representing system users."""

    __tablename__ = "users"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Basic info
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str | None] = mapped_column(String(100), unique=True, index=True)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    middle_name: Mapped[str | None] = mapped_column(String(100))

    # Authentication
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Profile info
    phone: Mapped[str | None] = mapped_column(String(20))
    avatar_url: Mapped[str | None] = mapped_column(String(500))
    timezone: Mapped[str | None] = mapped_column(String(50))
    locale: Mapped[str | None] = mapped_column(String(10))
    bio: Mapped[str | None] = mapped_column(Text)

    # Security
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Verification
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_token: Mapped[str | None] = mapped_column(String(255))
    verification_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Password reset
    reset_token: Mapped[str | None] = mapped_column(String(255))
    reset_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="Membership.user_id",
    )
    sessions: Mapped[list["Session"]] = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    api_keys: Mapped[list["APIKey"]] = relationship(
        "APIKey",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    oauth_identities: Mapped[list["OAuthIdentity"]] = relationship(
        "OAuthIdentity",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    oauth_clients: Mapped[list["OAuthClient"]] = relationship(
        "OAuthClient",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    @property
    def full_name(self) -> str:
        """Get full name."""
        if self.middle_name:
            return f"{self.first_name} {self.middle_name} {self.last_name}"
        return f"{self.first_name} {self.last_name}"

    @property
    def is_locked(self) -> bool:
        """Check if account is locked."""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until

    @property
    def can_login(self) -> bool:
        """Check if user can login."""
        from app.config.settings import settings

        # In testing environment, don't require email verification
        if settings.TESTING:
            return self.is_active and not self.is_locked

        return self.is_active and self.is_verified and not self.is_locked

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', active={self.is_active})>"
