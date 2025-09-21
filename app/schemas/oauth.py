"""OAuth schemas."""

from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl

from .common import BaseResponse


class OAuthClientCreateRequest(BaseModel):
    """Request model for OAuth client creation."""

    name: str = Field(..., description="Client application name")
    redirect_uris: list[HttpUrl] = Field(..., description="Allowed redirect URIs")
    allowed_scopes: list[str] = Field(..., description="Allowed OAuth scopes")
    description: str | None = Field(None, description="Client description")
    is_confidential: bool = Field(True, description="Whether client can keep secrets")


class OAuthClientResponse(BaseModel):
    """Response model for OAuth client."""

    client_id: str
    name: str
    description: str | None
    redirect_uris: list[str]
    allowed_scopes: list[str]
    is_confidential: bool
    created_at: datetime

    class Config:
        from_attributes = True


class OAuthClientCreateResponse(BaseResponse):
    """Response model for OAuth client creation."""

    client: dict  # Contains client_id, client_secret, etc.
    warning: str


class OAuthClientListResponse(BaseResponse):
    """Response model for OAuth client list."""

    clients: list[OAuthClientResponse]


class OAuthTokenResponse(BaseModel):
    """Response model for OAuth token exchange."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None
    scope: str | None = None


class OAuthUserInfoResponse(BaseModel):
    """Response model for OAuth userinfo endpoint."""

    sub: str  # Subject (user ID) - OAuth standard
    id: str | None = None  # User ID for compatibility
    email: str | None = None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture: str | None = None
    email_verified: bool | None = None
    # Legacy compatibility fields
    first_name: str | None = None
    last_name: str | None = None
    username: str | None = None


class OAuthErrorResponse(BaseModel):
    """Response model for OAuth errors."""

    error: str
    error_description: str | None = None
    error_uri: str | None = None


class OAuthMetadataResponse(BaseModel):
    """Response model for OAuth server metadata."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    revocation_endpoint: str
    scopes_supported: list[str]
    response_types_supported: list[str]
    grant_types_supported: list[str]
    code_challenge_methods_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
