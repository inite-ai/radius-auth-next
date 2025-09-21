"""OAuth Client model for OAuth 2.0 server implementation."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin


class OAuthClient(Base, TimestampMixin):
    """OAuth client applications that can authenticate users."""

    __tablename__ = "oauth_clients"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Client credentials
    client_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    client_secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Client info
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # OAuth configuration
    redirect_uris: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    allowed_scopes: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array
    grant_types: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array

    # Client type
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Security settings
    require_pkce: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    access_token_lifetime: Mapped[int] = mapped_column(Integer, default=3600)  # seconds
    refresh_token_lifetime: Mapped[int] = mapped_column(Integer, default=86400 * 30)  # seconds

    # Owner info
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    owner_organization_id: Mapped[int | None] = mapped_column(Integer)

    # Relationships
    authorization_codes: Mapped[list["OAuthAuthorizationCode"]] = relationship(
        "OAuthAuthorizationCode",
        back_populates="client",
        cascade="all, delete-orphan",
    )
    access_tokens: Mapped[list["OAuthAccessToken"]] = relationship(
        "OAuthAccessToken",
        back_populates="client",
        cascade="all, delete-orphan",
    )
    user: Mapped[Optional["User"]] = relationship("User", back_populates="oauth_clients")

    @property
    def redirect_uris_list(self) -> list[str]:
        """Get redirect URIs as list."""
        if not self.redirect_uris:
            return []
        try:
            import json

            return json.loads(self.redirect_uris)
        except (json.JSONDecodeError, TypeError):
            return []

    @redirect_uris_list.setter
    def redirect_uris_list(self, uris: list[str]) -> None:
        """Set redirect URIs from list."""
        import json

        self.redirect_uris = json.dumps(uris)

    @property
    def allowed_scopes_list(self) -> list[str]:
        """Get allowed scopes as list."""
        if not self.allowed_scopes:
            return []
        try:
            import json

            return json.loads(self.allowed_scopes)
        except (json.JSONDecodeError, TypeError):
            return []

    @allowed_scopes_list.setter
    def allowed_scopes_list(self, scopes: list[str]) -> None:
        """Set allowed scopes from list."""
        import json

        self.allowed_scopes = json.dumps(scopes)

    @property
    def grant_types_list(self) -> list[str]:
        """Get grant types as list."""
        if not self.grant_types:
            return ["authorization_code"]
        try:
            import json

            return json.loads(self.grant_types)
        except (json.JSONDecodeError, TypeError):
            return ["authorization_code"]

    @grant_types_list.setter
    def grant_types_list(self, types: list[str]) -> None:
        """Set grant types from list."""
        import json

        self.grant_types = json.dumps(types)

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        """Check if redirect URI is allowed."""
        return uri in self.redirect_uris_list

    def is_scope_allowed(self, scope: str) -> bool:
        """Check if scope is allowed."""
        return scope in self.allowed_scopes_list

    def __repr__(self) -> str:
        return f"<OAuthClient(id={self.id}, client_id='{self.client_id}', name='{self.name}')>"


class OAuthAuthorizationCode(Base, TimestampMixin):
    """OAuth authorization codes for code grant flow."""

    __tablename__ = "oauth_authorization_codes"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Foreign keys
    client_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("oauth_clients.id"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Code data
    code: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array

    # PKCE
    code_challenge: Mapped[str | None] = mapped_column(String(255))
    code_challenge_method: Mapped[str | None] = mapped_column(String(10))  # S256, plain

    # Expiration
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Status
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    client: Mapped[OAuthClient] = relationship("OAuthClient", back_populates="authorization_codes")

    @property
    def is_expired(self) -> bool:
        """Check if code is expired."""
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if code is valid."""
        return not self.is_used and not self.is_expired

    @property
    def scopes_list(self) -> list[str]:
        """Get scopes as list."""
        if not self.scopes:
            return []
        try:
            import json

            return json.loads(self.scopes)
        except (json.JSONDecodeError, TypeError):
            return []

    def __repr__(self) -> str:
        return f"<OAuthAuthorizationCode(id={self.id}, client_id='{self.client_id}', used={self.is_used})>"


class OAuthAccessToken(Base, TimestampMixin):
    """OAuth access tokens."""

    __tablename__ = "oauth_access_tokens"

    # Primary key
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Foreign keys
    client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("oauth_clients.id"), nullable=False, index=True
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Token data
    access_token: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    refresh_token: Mapped[str | None] = mapped_column(String(255), unique=True, index=True)
    scopes: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array

    # Expiration
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Status
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    client: Mapped[OAuthClient] = relationship("OAuthClient", back_populates="access_tokens")

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if token is valid."""
        return not self.is_revoked and not self.is_expired

    @property
    def scopes_list(self) -> list[str]:
        """Get scopes as list."""
        if not self.scopes:
            return []
        try:
            import json

            return json.loads(self.scopes)
        except (json.JSONDecodeError, TypeError):
            return []

    def revoke(self) -> None:
        """Revoke the token."""
        self.is_revoked = True

    def __repr__(self) -> str:
        return f"<OAuthAccessToken(id={self.id}, client_id='{self.client_id}', revoked={self.is_revoked})>"
