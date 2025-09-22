"""Authentication routes."""


from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.dependencies.auth import get_current_active_user, get_optional_current_user
from app.dependencies.services import get_auth_service
from app.models.user import User
from app.schemas.auth import (
    APIKeyCreateRequest,
    APIKeyCreateResponse,
    APIKeyListResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    RefreshTokenResponse,
    TokenResponse,
    VerifyTokenResponse,
)
from app.schemas.common import BaseResponse
from app.schemas.user import UserCreate, UserDetailResponse, UserResponse
from app.services.auth_service import AuthService
from app.services.client_service import ClientService
from app.utils.exceptions import AuthenticationError

router = APIRouter()


@router.post("/register", response_model=UserDetailResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Register a new user."""

    user = await auth_service.register_user(
        email=user_data.email,
        password=user_data.password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        username=user_data.username,
        middle_name=user_data.middle_name,
        phone=user_data.phone,
        timezone=user_data.timezone,
        locale=user_data.locale,
        bio=user_data.bio,
    )

    return UserDetailResponse(
        success=True,
        message="User registered successfully",
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Universal login endpoint with client-type detection.

    - Browser clients: Returns tokens + sets httpOnly cookies + CSRF protection
    - Mobile clients: Returns JWT tokens only (no cookies)
    - API clients: Returns JWT tokens with longer expiration
    """

    try:
        # Detect client type and device info
        client_type, device_name, device_type = ClientService.detect_client_info(request)

        # Authenticate user
        user = await auth_service.authenticate_user(
            email=login_data.email,
            password=login_data.password,
        )

        # Create session and tokens based on client type
        tokens = await auth_service.create_user_session(
            user=user,
            user_agent=request.headers.get("User-Agent"),
            ip_address=getattr(request.state, "client_ip", None),
            device_name=device_name,
            device_type=client_type,
            is_remember_me=login_data.remember_me,
        )

        # Set cookies for browser clients
        ClientService.set_session_cookies(
            response=response,
            refresh_token=tokens["refresh_token"],
            client_type=client_type,
            remember_me=login_data.remember_me,
        )

        # Determine if tokens should be returned in response
        response_tokens = tokens if ClientService.should_return_tokens(client_type) else None

        # Create complete login response
        return await auth_service.create_login_response(
            user=user,
            tokens=response_tokens,
            device_info={
                "device_name": device_name,
                "device_type": device_type,
                "user_agent": request.headers.get("User-Agent"),
            },
            client_type=client_type,
        )

    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
        )
    except Exception as e:
        # Log the full exception for debugging
        import traceback

        print(f"Login error: {e}")
        print(traceback.format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}",
        )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_tokens(
    refresh_data: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Refresh access token using refresh token."""

    try:
        tokens = await auth_service.refresh_tokens(
            refresh_token=refresh_data.refresh_token,
            organization_id=refresh_data.organization_id,
        )

        return RefreshTokenResponse(
            success=True,
            message="Tokens refreshed successfully",
            tokens=TokenResponse(**tokens),
        )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    response: Response,
    refresh_token: str | None = None,
    current_user: User | None = Depends(get_optional_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Logout user by revoking session."""
    from app.config.settings import settings

    # Try to get refresh token from cookie if not provided
    if not refresh_token:
        refresh_token = request.cookies.get(settings.SESSION_COOKIE_NAME)

    # If no refresh token and we have a current user from JWT, try logout by access token
    if not refresh_token and current_user:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            access_token = auth_header.split(" ")[1]
            await auth_service.logout_by_access_token(access_token, current_user.id)
    elif refresh_token:
        # Traditional logout with refresh token (for browser clients)
        await auth_service.logout(refresh_token)

    # Clear cookies
    ClientService.clear_session_cookies(response)

    return LogoutResponse(
        success=True,
        message="Logout successful",
    )


@router.post("/logout-all", response_model=LogoutResponse)
async def logout_all_sessions(
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Logout user from all sessions."""

    revoked_count = await auth_service.logout_all_sessions(current_user.id)

    return LogoutResponse(
        success=True,
        message=f"Logged out from {revoked_count} sessions",
        revoked_sessions=revoked_count,
    )


@router.post("/password-reset/request", response_model=BaseResponse)
async def request_password_reset(
    reset_request: PasswordResetRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Request password reset token."""

    # Always return success to avoid email enumeration
    await auth_service.create_password_reset_token(reset_request.email)

    return BaseResponse(
        success=True,
        message="If the email exists, a reset token has been sent",
    )


@router.post("/password-reset/confirm", response_model=BaseResponse)
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirmRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """Confirm password reset with token."""

    try:
        await auth_service.reset_password(reset_confirm.token, reset_confirm.new_password)

        return BaseResponse(
            success=True,
            message="Password reset successful",
        )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )


@router.get("/me", response_model=UserDetailResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
):
    """Get current user information."""

    return UserDetailResponse(
        success=True,
        message="User information retrieved successfully",
        user=UserResponse.model_validate(current_user),
    )


@router.post("/verify-token", response_model=VerifyTokenResponse)
async def verify_token(
    current_user: User = Depends(get_current_active_user),
):
    """Verify if current token is valid."""

    return VerifyTokenResponse(
        success=True,
        message="Token is valid",
        user_id=current_user.id,
    )


# ================== MOBILE/API CLIENT SPECIFIC ENDPOINTS ==================


# Mobile login removed - use universal /login endpoint instead
# It auto-detects client type and returns appropriate response format


@router.post("/api-key/create", response_model=APIKeyCreateResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Create API key for machine-to-machine authentication.

    API keys have format: pauth_xxx... and are stored as hashes.
    """

    # Use auth service to create the API key
    api_key, api_key_record = await auth_service.create_api_key(
        user_id=current_user.id,
        name=request.name,
        scopes=request.scopes,
        expires_days=request.expires_days,
    )

    key_info = auth_service._create_api_key_response(api_key_record)

    return APIKeyCreateResponse(
        success=True,
        message="API key created successfully",
        api_key=api_key,
        key_info=key_info,
        warning="Store this API key securely. It will not be shown again.",
    )


@router.get("/api-keys", response_model=APIKeyListResponse)
async def list_api_keys(
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """List user's API keys (without the actual keys)."""
    api_key_responses = await auth_service.get_api_keys_list(current_user.id)

    return APIKeyListResponse(
        success=True,
        message="API keys retrieved successfully",
        api_keys=api_key_responses,
    )


@router.delete("/api-keys/{key_id}", response_model=BaseResponse)
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Revoke an API key."""

    revoked = await auth_service.revoke_api_key(current_user.id, key_id)

    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    return BaseResponse(
        success=True,
        message="API key revoked successfully",
    )
