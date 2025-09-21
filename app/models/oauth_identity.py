"""OAuth Identity model for social authentication."""

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class OAuthIdentity(Base, TimestampMixin):
    """OAuth Identity model for linking users with OAuth providers."""

    __tablename__ = "oauth_identities"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Foreign keys
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # OAuth provider info
    provider: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # google, github, etc.
    provider_user_id: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )  # OAuth provider's user ID

    # Provider data
    email: Mapped[str | None] = mapped_column(String(255))
    username: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))
    avatar_url: Mapped[str | None] = mapped_column(String(500))

    # OAuth tokens (optional, for API access)
    access_token: Mapped[str | None] = mapped_column(Text)  # Encrypted in production
    refresh_token: Mapped[str | None] = mapped_column(Text)  # Encrypted in production
    token_expires_at: Mapped[str | None] = mapped_column(String(255))

    # Provider-specific data (JSON)
    provider_data: Mapped[str | None] = mapped_column(Text)  # JSON with additional provider data

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="oauth_identities")

    # Constraints
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="unique_provider_user"),
    )

    @property
    def provider_data_dict(self) -> dict:
        """Get provider data as dictionary."""
        if not self.provider_data:
            return {}
        try:
            import json

            return json.loads(self.provider_data)
        except (json.JSONDecodeError, TypeError):
            return {}

    @provider_data_dict.setter
    def provider_data_dict(self, data: dict) -> None:
        """Set provider data from dictionary."""
        import json

        self.provider_data = json.dumps(data)

    def __repr__(self) -> str:
        return f"<OAuthIdentity(id={self.id}, provider='{self.provider}', user_id={self.user_id})>"
