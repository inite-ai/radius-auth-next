"""OAuth 2.0 server implementation."""

import hashlib
import urllib.parse
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oauth_client import OAuthAccessToken, OAuthAuthorizationCode, OAuthClient
from app.models.user import User
from app.schemas.oauth import OAuthClientResponse, OAuthUserInfoResponse
from app.utils.exceptions import AuthenticationError, ValidationError
from app.utils.security import constant_time_compare, generate_random_string, hash_token


class OAuthService:
    """OAuth 2.0 server service."""

    AVAILABLE_SCOPES = {
        "profile": "Access to user profile information",
        "email": "Access to user email address",
        "organizations": "Access to user's organizations",
        "users:read": "Read access to users",
        "users:write": "Write access to users",
        "organizations:read": "Read access to organizations",
        "organizations:write": "Write access to organizations",
        "mcp:connect": "Connect as MCP server",
        "admin": "Administrative access",
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_client(
        self,
        name: str,
        redirect_uris: list[str],
        allowed_scopes: list[str],
        description: str | None = None,
        is_confidential: bool = True,
        user_id: int | None = None,
    ) -> tuple[OAuthClient, str]:
        """Create OAuth client and return client with secret."""

        # Validate scopes
        invalid_scopes = set(allowed_scopes) - set(self.AVAILABLE_SCOPES.keys())
        if invalid_scopes:
            raise ValidationError(f"Invalid scopes: {invalid_scopes}")

        # Generate client credentials
        client_id = f"oauth_{generate_random_string(32)}"
        client_secret = generate_random_string(64)
        client_secret_hash = hash_token(client_secret)

        # Create client
        client = OAuthClient(
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            name=name,
            description=description,
            redirect_uris_list=redirect_uris,
            allowed_scopes_list=allowed_scopes,
            grant_types_list=["authorization_code", "refresh_token"],
            is_confidential=is_confidential,
            user_id=user_id,
        )

        self.db.add(client)
        await self.db.commit()
        await self.db.refresh(client)

        return client, client_secret

    async def get_client(self, client_id: str) -> OAuthClient | None:
        """Get OAuth client by ID."""
        result = await self.db.execute(
            select(OAuthClient).where(
                OAuthClient.client_id == client_id,
                OAuthClient.is_active,
            )
        )
        return result.scalar_one_or_none()

    async def authenticate_client(self, client_id: str, client_secret: str) -> OAuthClient | None:
        """Authenticate OAuth client."""
        client = await self.get_client(client_id)

        if not client or not client.is_confidential:
            return None

        # Verify client secret
        if not constant_time_compare(hash_token(client_secret), client.client_secret_hash):
            return None

        return client

    def build_authorization_url(
        self,
        client_id: str,
        redirect_uri: str,
        scopes: list[str],
        state: str | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str = "S256",
    ) -> str:
        """Build OAuth authorization URL."""

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
        }

        if state:
            params["state"] = state

        if code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = code_challenge_method

        # This would be your auth server's authorize endpoint
        base_url = "https://auth.yourplatform.com/oauth/authorize"
        return f"{base_url}?{urllib.parse.urlencode(params)}"

    async def create_authorization_code(
        self,
        client: OAuthClient,
        user: User,
        redirect_uri: str,
        scopes: list[str],
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
    ) -> str:
        """Create authorization code."""

        # Validate redirect URI
        if not client.is_redirect_uri_allowed(redirect_uri):
            raise ValidationError("Invalid redirect URI")

        # Validate scopes
        invalid_scopes = set(scopes) - set(client.allowed_scopes_list)
        if invalid_scopes:
            raise ValidationError(f"Invalid scopes: {invalid_scopes}")

        # Generate code
        code = generate_random_string(64)
        expires_at = datetime.utcnow() + timedelta(minutes=10)  # 10 minute expiration

        # Create authorization code record
        auth_code = OAuthAuthorizationCode(
            client_id=client.client_id,
            user_id=user.id,
            code=code,
            redirect_uri=redirect_uri,
            scopes=self._scopes_to_json(scopes),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at,
        )

        self.db.add(auth_code)
        await self.db.commit()

        return code

    async def exchange_code_for_tokens(
        self,
        client: OAuthClient,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> dict[str, any]:
        """Exchange authorization code for access tokens."""

        # Get authorization code
        result = await self.db.execute(
            select(OAuthAuthorizationCode).where(
                OAuthAuthorizationCode.code == code,
                OAuthAuthorizationCode.client_id == client.client_id,
            )
        )
        auth_code = result.scalar_one_or_none()

        if not auth_code or not auth_code.is_valid:
            raise AuthenticationError("Invalid or expired authorization code")

        # Verify redirect URI
        if auth_code.redirect_uri != redirect_uri:
            raise ValidationError("Redirect URI mismatch")

        # Verify PKCE if required
        if client.require_pkce or auth_code.code_challenge:
            if not code_verifier or not auth_code.code_challenge:
                raise ValidationError("PKCE required")

            if auth_code.code_challenge_method == "S256":
                import base64

                challenge = (
                    base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
                    .decode("utf-8")
                    .rstrip("=")
                )
            else:
                challenge = code_verifier

            if not constant_time_compare(challenge, auth_code.code_challenge):
                raise ValidationError("Invalid PKCE verifier")

        from app.utils.transaction_manager import atomic_operation

        # Atomically mark code as used and create access token
        async with atomic_operation(self.db):
            # Mark code as used
            auth_code.is_used = True

            # Create access token
            access_token = generate_random_string(64)
            refresh_token = generate_random_string(64)
            expires_at = datetime.utcnow() + timedelta(seconds=client.access_token_lifetime)

            oauth_token = OAuthAccessToken(
                client_id=client.client_id,
                user_id=auth_code.user_id,
                access_token=access_token,
                refresh_token=refresh_token,
                scopes=auth_code.scopes,
                expires_at=expires_at,
            )

            self.db.add(oauth_token)

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime,
            "refresh_token": refresh_token,
            "scope": " ".join(auth_code.scopes_list),
        }

    async def refresh_access_token(
        self,
        client: OAuthClient,
        refresh_token: str,
    ) -> dict[str, any]:
        """Refresh access token."""

        # Get token by refresh token
        result = await self.db.execute(
            select(OAuthAccessToken).where(
                OAuthAccessToken.refresh_token == refresh_token,
                OAuthAccessToken.client_id == client.client_id,
                OAuthAccessToken.is_revoked == False,
            )
        )
        token = result.scalar_one_or_none()

        if not token:
            raise AuthenticationError("Invalid refresh token")

        # Create new access token
        new_access_token = generate_random_string(64)
        new_refresh_token = generate_random_string(64)
        expires_at = datetime.utcnow() + timedelta(seconds=client.access_token_lifetime)

        # Update token
        token.access_token = new_access_token
        token.refresh_token = new_refresh_token
        token.expires_at = expires_at

        await self.db.commit()

        return {
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime,
            "refresh_token": new_refresh_token,
            "scope": " ".join(token.scopes_list),
        }

    async def validate_access_token(
        self, access_token: str
    ) -> tuple[OAuthAccessToken, User] | None:
        """Validate OAuth access token and return token + user."""

        result = await self.db.execute(
            select(OAuthAccessToken, User)
            .join(User, OAuthAccessToken.user_id == User.id)
            .where(
                OAuthAccessToken.access_token == access_token,
                OAuthAccessToken.is_revoked == False,
            )
        )
        token_user = result.first()

        if not token_user:
            return None

        token, user = token_user

        if not token.is_valid or not user.can_login:
            return None

        return token, user

    async def revoke_token(self, access_token: str) -> bool:
        """Revoke OAuth access token."""

        result = await self.db.execute(
            select(OAuthAccessToken).where(OAuthAccessToken.access_token == access_token)
        )
        token = result.scalar_one_or_none()

        if token:
            token.revoke()
            await self.db.commit()
            return True

        return False

    async def list_user_clients(self, user_id: int) -> list[OAuthClient]:
        """List OAuth clients for user."""

        result = await self.db.execute(
            select(OAuthClient)
            .where(
                OAuthClient.user_id == user_id,
                OAuthClient.is_active,
            )
            .order_by(OAuthClient.created_at.desc())
        )
        return list(result.scalars().all())

    async def delete_user_client(self, user_id: int, client_id: str) -> bool:
        """Delete OAuth client for user."""

        result = await self.db.execute(
            select(OAuthClient).where(
                OAuthClient.client_id == client_id,
                OAuthClient.user_id == user_id,
            )
        )
        client = result.scalar_one_or_none()

        if not client:
            return False

        client.is_active = False
        await self.db.commit()

        return True

    async def get_user_permissions(self, token: OAuthAccessToken, user: User) -> dict[str, any]:
        """Get user info based on token scopes."""

        scopes = token.scopes_list
        user_info = {}

        if "profile" in scopes:
            user_info.update(
                {
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "full_name": user.full_name,
                    "username": user.username,
                    "avatar_url": user.avatar_url,
                }
            )

        if "email" in scopes:
            user_info["email"] = user.email
            user_info["email_verified"] = user.is_verified

        if "organizations" in scopes:
            # Get user's organizations
            user_info["organizations"] = [
                {
                    "id": membership.organization.id,
                    "name": membership.organization.name,
                    "slug": membership.organization.slug,
                    "role": membership.role,
                }
                for membership in user.memberships
                if membership.is_active and membership.organization.is_active
            ]

        return user_info

    def _scopes_to_json(self, scopes: list[str]) -> str:
        """Convert scopes list to JSON."""
        import json

        return json.dumps(scopes)

    def _create_client_response(self, client: OAuthClient) -> OAuthClientResponse:
        """Create OAuthClientResponse from OAuthClient model."""
        return OAuthClientResponse(
            client_id=client.client_id,
            name=client.name,
            description=client.description,
            redirect_uris=client.redirect_uris_list,
            allowed_scopes=client.allowed_scopes_list,
            is_confidential=client.is_confidential,
            created_at=client.created_at,
        )

    async def get_user_clients_list(self, user_id: int) -> list[OAuthClientResponse]:
        """Get list of user's OAuth clients as response objects."""
        clients = await self.list_user_clients(user_id)
        return [self._create_client_response(client) for client in clients]

    async def create_user_info_response(
        self,
        token: OAuthAccessToken,
        user: User,
    ) -> OAuthUserInfoResponse:
        """Create OAuth user info response based on token scopes."""
        user_info = await self.get_user_permissions(token, user)

        # Map to OAuth standard userinfo format plus extra fields for compatibility
        return OAuthUserInfoResponse(
            sub=str(user.id),  # subject (user ID) - OAuth standard
            id=str(user.id),  # user ID for compatibility
            email=user_info.get("email"),
            name=user_info.get("full_name"),
            given_name=user_info.get("first_name"),
            family_name=user_info.get("last_name"),
            picture=user_info.get("avatar_url"),
            email_verified=user_info.get("email_verified"),
            # Legacy compatibility fields
            first_name=user_info.get("first_name"),
            last_name=user_info.get("last_name"),
            username=user_info.get("username"),
        )

    def generate_consent_html(
        self,
        client: OAuthClient,
        user: User,
        requested_scopes: list[str],
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str | None,
        code_challenge: str | None,
        code_challenge_method: str,
    ) -> str:
        """Generate OAuth consent screen HTML."""
        scope_descriptions = "".join(
            f'<div class="scope">• {scope_name}: {self.AVAILABLE_SCOPES.get(scope_name, "Unknown permission")}</div>'
            for scope_name in requested_scopes
        )

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorize {client.name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }}
                .app-info {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .scopes {{ margin: 20px 0; }}
                .scope {{ margin: 5px 0; padding: 5px; background: #e7f3ff; border-radius: 3px; }}
                .buttons {{ margin: 20px 0; }}
                button {{ padding: 10px 20px; margin: 5px; border: none; border-radius: 3px; cursor: pointer; }}
                .allow {{ background: #007bff; color: white; }}
                .deny {{ background: #6c757d; color: white; }}
            </style>
        </head>
        <body>
            <h2>Authorize Application</h2>

            <div class="app-info">
                <h3>{client.name}</h3>
                <p>{client.description or "No description provided"}</p>
            </div>

            <p><strong>{client.name}</strong> is requesting access to your account.</p>

            <div class="scopes">
                <h4>Requested permissions:</h4>
                {scope_descriptions}
            </div>

            <div class="buttons">
                <form method="post" action="/api/v1/oauth/authorize" style="display: inline;">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="hidden" name="scope" value="{scope}">
                    <input type="hidden" name="state" value="{state or ''}">
                    <input type="hidden" name="code_challenge" value="{code_challenge or ''}">
                    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
                    <input type="hidden" name="action" value="allow">
                    <button type="submit" class="allow">Allow</button>
                </form>

                <form method="post" action="/api/v1/oauth/authorize" style="display: inline;">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="hidden" name="state" value="{state or ''}">
                    <input type="hidden" name="action" value="deny">
                    <button type="submit" class="deny">Deny</button>
                </form>
            </div>

            <p><small>You are logged in as {user.email}</small></p>
        </body>
        </html>
        """
