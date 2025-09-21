"""Organization model."""

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class Organization(Base, TimestampMixin):
    """Organization model representing tenants/companies."""

    __tablename__ = "organizations"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Basic info
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # Settings
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_personal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Contact info
    website: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))
    phone: Mapped[str | None] = mapped_column(String(20))

    # Branding
    logo_url: Mapped[str | None] = mapped_column(String(500))
    primary_color: Mapped[str | None] = mapped_column(String(7))  # Hex color

    # Billing/Plan info
    plan: Mapped[str] = mapped_column(String(50), default="free", nullable=False)
    max_users: Mapped[int | None] = mapped_column(Integer)

    # Settings JSON could be added here for flexible configuration

    # Relationships
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership",
        back_populates="organization",
        cascade="all, delete-orphan",
    )

    @property
    def user_count(self) -> int:
        """Get number of active users in organization."""
        return len([m for m in self.memberships if m.user.is_active])

    @property
    def can_add_users(self) -> bool:
        """Check if organization can add more users."""
        if not self.max_users:
            return True
        return self.user_count < self.max_users

    def __repr__(self) -> str:
        return f"<Organization(id={self.id}, name='{self.name}', slug='{self.slug}')>"
