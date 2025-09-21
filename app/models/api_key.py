"""API Key model for machine-to-machine authentication."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class APIKey(Base, TimestampMixin):
    """API Key model for machine authentication and integrations."""

    __tablename__ = "api_keys"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Foreign keys
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Key data
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    # Permissions and scopes
    scopes: Mapped[str | None] = mapped_column(Text)  # JSON array of scopes
    description: Mapped[str | None] = mapped_column(Text)

    # Status and expiration
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Usage tracking
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    usage_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Rate limiting
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="api_keys")

    @property
    def is_expired(self) -> bool:
        """Check if API key is expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if API key is valid (active and not expired)."""
        return self.is_active and not self.is_expired

    @property
    def scopes_list(self) -> list[str]:
        """Get scopes as a list."""
        if not self.scopes:
            return []
        try:
            import json

            return json.loads(self.scopes)
        except (json.JSONDecodeError, TypeError):
            return []

    @scopes_list.setter
    def scopes_list(self, scopes: list[str]) -> None:
        """Set scopes from a list."""
        import json

        self.scopes = json.dumps(scopes)

    def has_scope(self, scope: str) -> bool:
        """Check if API key has a specific scope."""
        return scope in self.scopes_list

    def record_usage(self) -> None:
        """Record API key usage."""
        self.last_used_at = datetime.utcnow()
        self.usage_count += 1

    def revoke(self) -> None:
        """Revoke the API key."""
        self.is_active = False

    def __repr__(self) -> str:
        return f"<APIKey(id={self.id}, name='{self.name}', prefix='{self.prefix}', active={self.is_active})>"
