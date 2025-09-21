"""OAuth 2.0 server endpoints."""

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import get_current_active_user
from app.dependencies.database import get_db
from app.models.user import User
from app.services.oauth_service import OAuthService
from app.utils.exceptions import AuthenticationError, ValidationError

router = APIRouter()


class OAuthClientCreateRequest(BaseModel):
    """Request model for OAuth client creation."""

    name: str
    redirect_uris: list[str]
    allowed_scopes: list[str]
    description: str | None = None
    is_confidential: bool = True


# ==================== CLIENT MANAGEMENT ====================


@router.post("/clients")
async def create_oauth_client(
    request: OAuthClientCreateRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Create OAuth client application."""

    oauth_service = OAuthService(db)

    try:
        client, client_secret = await oauth_service.create_client(
            name=request.name,
            redirect_uris=request.redirect_uris,
            allowed_scopes=request.allowed_scopes,
            description=request.description,
            is_confidential=request.is_confidential,
            user_id=current_user.id,
        )

        return {
            "success": True,
            "message": "OAuth client created successfully",
            "client": {
                "client_id": client.client_id,
                "client_secret": client_secret,  # Only shown once!
                "name": client.name,
                "description": client.description,
                "redirect_uris": client.redirect_uris_list,
                "allowed_scopes": client.allowed_scopes_list,
                "is_confidential": client.is_confidential,
                "created_at": client.created_at,
            },
            "warning": "Store client_secret securely. It will not be shown again.",
        }

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )


@router.get("/clients")
async def list_oauth_clients(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List user's OAuth clients."""

    from sqlalchemy import select

    from app.models.oauth_client import OAuthClient

    result = await db.execute(
        select(OAuthClient)
        .where(
            OAuthClient.user_id == current_user.id,
            OAuthClient.is_active,
        )
        .order_by(OAuthClient.created_at.desc())
    )
    clients = result.scalars().all()

    return {
        "success": True,
        "clients": [
            {
                "client_id": client.client_id,
                "name": client.name,
                "description": client.description,
                "redirect_uris": client.redirect_uris_list,
                "allowed_scopes": client.allowed_scopes_list,
                "is_confidential": client.is_confidential,
                "created_at": client.created_at,
            }
            for client in clients
        ],
    }


@router.delete("/clients/{client_id}")
async def delete_oauth_client(
    client_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete OAuth client."""

    from sqlalchemy import select

    from app.models.oauth_client import OAuthClient

    result = await db.execute(
        select(OAuthClient).where(
            OAuthClient.client_id == client_id,
            OAuthClient.user_id == current_user.id,
        )
    )
    client = result.scalar_one_or_none()

    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OAuth client not found",
        )

    client.is_active = False
    await db.commit()

    return {
        "success": True,
        "message": "OAuth client deleted successfully",
    }


# ==================== OAUTH 2.0 ENDPOINTS ====================


@router.get("/authorize")
async def authorize(
    client_id: str = Query(..., description="OAuth client ID"),
    redirect_uri: str = Query(..., description="Redirect URI"),
    response_type: str = Query("code", description="Response type"),
    scope: str = Query(..., description="Requested scopes"),
    state: str | None = Query(None, description="State parameter"),
    code_challenge: str | None = Query(None, description="PKCE code challenge"),
    code_challenge_method: str = Query("S256", description="PKCE method"),
    current_user: User | None = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    OAuth authorization endpoint.

    If user is logged in, shows consent screen.
    If not logged in, redirects to login.
    """

    oauth_service = OAuthService(db)

    # Validate client
    client = await oauth_service.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid client_id",
        )

    # Validate redirect URI
    if not client.is_redirect_uri_allowed(redirect_uri):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid redirect_uri",
        )

    # Parse scopes
    requested_scopes = scope.split()

    # Validate scopes
    invalid_scopes = set(requested_scopes) - set(client.allowed_scopes_list)
    if invalid_scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scopes: {invalid_scopes}",
        )

    # If user not logged in, redirect to login
    if not current_user:
        # Store OAuth params in session/state and redirect to login
        login_url = "/api/v1/auth/login?next=/oauth/authorize"
        return RedirectResponse(url=login_url, status_code=302)

    # Show consent screen (simplified HTML for demo)
    consent_html = f"""
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
            {"".join(f'<div class="scope">• {scope}: {oauth_service.AVAILABLE_SCOPES.get(scope, "Unknown permission")}</div>' for scope in requested_scopes)}
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

        <p><small>You are logged in as {current_user.email}</small></p>
    </body>
    </html>
    """

    return HTMLResponse(content=consent_html)


@router.post("/authorize")
async def authorize_post(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    action: str = Form(...),
    scope: str = Form(...),
    state: str | None = Form(None),
    code_challenge: str | None = Form(None),
    code_challenge_method: str = Form("S256"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Handle authorization consent."""

    oauth_service = OAuthService(db)

    # Get client
    client = await oauth_service.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid client_id",
        )

    # If user denied
    if action == "deny":
        error_params = {"error": "access_denied"}
        if state:
            error_params["state"] = state
        redirect_url = f"{redirect_uri}?{'&'.join(f'{k}={v}' for k, v in error_params.items())}"
        return RedirectResponse(url=redirect_url, status_code=302)

    # If user allowed
    if action == "allow":
        try:
            requested_scopes = scope.split()

            # Create authorization code
            code = await oauth_service.create_authorization_code(
                client=client,
                user=current_user,
                redirect_uri=redirect_uri,
                scopes=requested_scopes,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )

            # Redirect with code
            params = {"code": code}
            if state:
                params["state"] = state

            redirect_url = f"{redirect_uri}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
            return RedirectResponse(url=redirect_url, status_code=302)

        except ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=e.message,
            )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid action",
    )


@router.post("/token")
async def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    refresh_token: str | None = Form(None),
    code_verifier: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """OAuth token endpoint."""

    oauth_service = OAuthService(db)

    try:
        # Authenticate client
        if client_secret:
            client = await oauth_service.authenticate_client(client_id, client_secret)
        else:
            client = await oauth_service.get_client(client_id)

        if not client:
            raise AuthenticationError("Invalid client credentials")

        # Handle different grant types
        if grant_type == "authorization_code":
            if not code or not redirect_uri:
                raise ValidationError("Missing code or redirect_uri")

            tokens = await oauth_service.exchange_code_for_tokens(
                client=client,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
            )

            return tokens

        elif grant_type == "refresh_token":
            if not refresh_token:
                raise ValidationError("Missing refresh_token")

            tokens = await oauth_service.refresh_access_token(
                client=client,
                refresh_token=refresh_token,
            )

            return tokens

        else:
            raise ValidationError(f"Unsupported grant_type: {grant_type}")

    except (AuthenticationError, ValidationError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )


@router.get("/userinfo")
async def userinfo(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """OAuth userinfo endpoint."""

    # Get access token from Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )

    access_token = auth_header[7:]  # Remove "Bearer "

    oauth_service = OAuthService(db)
    token_user = await oauth_service.validate_access_token(access_token)

    if not token_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        )

    token, user = token_user

    # Return user info based on scopes
    user_info = await oauth_service.get_user_permissions(token, user)

    return user_info


@router.post("/revoke")
async def revoke(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """OAuth token revocation endpoint."""

    oauth_service = OAuthService(db)

    # Authenticate client (optional for public clients)
    if client_secret:
        client = await oauth_service.authenticate_client(client_id, client_secret)
        if not client:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client credentials",
            )

    # Revoke token
    revoked = await oauth_service.revoke_token(token)

    # Always return 200 per OAuth spec
    return {"revoked": revoked}


# ==================== DISCOVERY & METADATA ====================


@router.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
    """OAuth 2.0 Authorization Server Metadata."""

    base_url = "https://auth.yourplatform.com/api/v1/oauth"  # Configure this

    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "revocation_endpoint": f"{base_url}/revoke",
        "scopes_supported": list(OAuthService.AVAILABLE_SCOPES.keys()),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
    }
