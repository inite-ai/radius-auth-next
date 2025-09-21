"""Membership model for user-organization relationships."""

from enum import Enum
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class Role(str, Enum):
    """User roles within an organization."""

    OWNER = "owner"  # Full access, can delete org, manage billing
    ADMIN = "admin"  # Full access except org deletion and billing
    EDITOR = "editor"  # Can create/edit content, manage users
    VIEWER = "viewer"  # Read-only access


class Membership(Base, TimestampMixin):
    """Membership model representing user roles in organizations."""

    __tablename__ = "memberships"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Foreign keys
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Role and status
    role: Mapped[Role] = mapped_column(String(20), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Invitation info
    invited_by_user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    invitation_token: Mapped[str | None] = mapped_column(String(255))
    invitation_accepted_at: Mapped[str | None] = mapped_column(String(255))

    # Relationships
    user: Mapped["User"] = relationship(
        "User", back_populates="memberships", foreign_keys=[user_id]
    )
    organization: Mapped["Organization"] = relationship(
        "Organization", back_populates="memberships"
    )
    invited_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[invited_by_user_id])

    # Constraints
    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="unique_user_org_membership"),
    )

    @property
    def is_owner(self) -> bool:
        """Check if user is owner of the organization."""
        return self.role == Role.OWNER

    @property
    def is_admin_or_owner(self) -> bool:
        """Check if user has admin or owner role."""
        return self.role in (Role.OWNER, Role.ADMIN)

    @property
    def can_manage_users(self) -> bool:
        """Check if user can manage other users."""
        return self.role in (Role.OWNER, Role.ADMIN, Role.EDITOR)

    @property
    def can_edit_content(self) -> bool:
        """Check if user can edit content."""
        return self.role in (Role.OWNER, Role.ADMIN, Role.EDITOR)

    @property
    def is_read_only(self) -> bool:
        """Check if user has read-only access."""
        return self.role == Role.VIEWER

    def __repr__(self) -> str:
        return f"<Membership(user_id={self.user_id}, org_id={self.organization_id}, role='{self.role}')>"
