"""OAuth 2.0 server endpoints."""

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_oauth_service
from app.models.user import User
from app.schemas.common import BaseResponse
from app.schemas.oauth import (
    OAuthClientCreateRequest,
    OAuthClientCreateResponse,
    OAuthClientListResponse,
    OAuthMetadataResponse,
    OAuthTokenResponse,
    OAuthUserInfoResponse,
)
from app.services.oauth_service import OAuthService
from app.utils.exceptions import AuthenticationError, ValidationError

router = APIRouter()


# ==================== CLIENT MANAGEMENT ====================


@router.post(
    "/clients", response_model=OAuthClientCreateResponse, status_code=status.HTTP_201_CREATED
)
async def create_oauth_client(
    request: OAuthClientCreateRequest,
    current_user: User = Depends(get_current_active_user),
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    """Create OAuth client application."""

    try:
        client, client_secret = await oauth_service.create_client(
            name=request.name,
            redirect_uris=[str(uri) for uri in request.redirect_uris],
            allowed_scopes=request.allowed_scopes,
            description=request.description,
            is_confidential=request.is_confidential,
            user_id=current_user.id,
        )

        return OAuthClientCreateResponse(
            success=True,
            message="OAuth client created successfully",
            client={
                "client_id": client.client_id,
                "client_secret": client_secret,  # Only shown once!
                "name": client.name,
                "description": client.description,
                "redirect_uris": client.redirect_uris_list,
                "allowed_scopes": client.allowed_scopes_list,
                "is_confidential": client.is_confidential,
                "created_at": client.created_at,
            },
            warning="Store client_secret securely. It will not be shown again.",
        )

    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )


@router.get("/clients", response_model=OAuthClientListResponse)
async def list_oauth_clients(
    current_user: User = Depends(get_current_active_user),
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    """List user's OAuth clients."""
    client_responses = await oauth_service.get_user_clients_list(current_user.id)

    return OAuthClientListResponse(
        success=True,
        message="OAuth clients retrieved successfully",
        clients=client_responses,
    )


@router.delete("/clients/{client_id}", response_model=BaseResponse)
async def delete_oauth_client(
    client_id: str,
    current_user: User = Depends(get_current_active_user),
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    """Delete OAuth client."""

    deleted = await oauth_service.delete_user_client(current_user.id, client_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OAuth client not found",
        )

    return BaseResponse(
        success=True,
        message="OAuth client deleted successfully",
    )


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
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    """
    OAuth authorization endpoint.

    If user is logged in, shows consent screen.
    If not logged in, redirects to login.
    """

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

    # Generate consent screen using service
    consent_html = oauth_service.generate_consent_html(
        client=client,
        user=current_user,
        requested_scopes=requested_scopes,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

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
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    """Handle authorization consent."""

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


@router.post("/token", response_model=OAuthTokenResponse)
async def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    refresh_token: str | None = Form(None),
    code_verifier: str | None = Form(None),
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    """OAuth token endpoint."""

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

            return OAuthTokenResponse(**tokens)

        elif grant_type == "refresh_token":
            if not refresh_token:
                raise ValidationError("Missing refresh_token")

            tokens = await oauth_service.refresh_access_token(
                client=client,
                refresh_token=refresh_token,
            )

            return OAuthTokenResponse(**tokens)

        else:
            raise ValidationError(f"Unsupported grant_type: {grant_type}")

    except (AuthenticationError, ValidationError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )


@router.get("/userinfo", response_model=OAuthUserInfoResponse)
async def userinfo(
    request: Request,
    oauth_service: OAuthService = Depends(get_oauth_service),
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
    token_user = await oauth_service.validate_access_token(access_token)

    if not token_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        )

    token, user = token_user

    # Create user info response using service
    return await oauth_service.create_user_info_response(token, user)


@router.post("/revoke")
async def revoke(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    oauth_service: OAuthService = Depends(get_oauth_service),
):
    """OAuth token revocation endpoint."""

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


@router.get("/.well-known/oauth-authorization-server", response_model=OAuthMetadataResponse)
async def oauth_metadata():
    """OAuth 2.0 Authorization Server Metadata."""

    base_url = "https://auth.yourplatform.com/api/v1/oauth"  # Configure this

    return OAuthMetadataResponse(
        issuer=base_url,
        authorization_endpoint=f"{base_url}/authorize",
        token_endpoint=f"{base_url}/token",
        userinfo_endpoint=f"{base_url}/userinfo",
        revocation_endpoint=f"{base_url}/revoke",
        scopes_supported=list(OAuthService.AVAILABLE_SCOPES.keys()),
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", "refresh_token"],
        code_challenge_methods_supported=["S256"],
        token_endpoint_auth_methods_supported=["client_secret_post", "none"],
    )
