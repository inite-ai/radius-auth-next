"""Authentication routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import get_current_active_user, get_optional_current_user
from app.dependencies.database import get_db
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    RefreshTokenResponse,
    TokenResponse,
    UserProfile,
)
from app.services.auth_service import AuthService
from app.utils.device_detection import detect_client_type, get_device_info, should_use_cookies
from app.utils.exceptions import AuthenticationError

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Universal login endpoint with client-type detection.
    
    - Browser clients: Returns tokens + sets httpOnly cookies + CSRF protection
    - Mobile clients: Returns JWT tokens only (no cookies)
    - API clients: Returns JWT tokens with longer expiration
    """
    
    auth_service = AuthService(db)
    
    try:
        # Detect client type
        user_agent = request.headers.get("User-Agent")
        client_type = detect_client_type(user_agent, request.headers.get("Accept"))
        device_name, device_type = get_device_info(user_agent)
        
        # Authenticate user
        user = await auth_service.authenticate_user(
            email=login_data.email,
            password=login_data.password,
        )
        
        # Create session and tokens based on client type
        tokens = await auth_service.create_user_session(
            user=user,
            user_agent=user_agent,
            ip_address=getattr(request.state, "client_ip", None),
            device_name=device_name,
            device_type=client_type,
            is_remember_me=login_data.remember_me,
        )
        
        # For browser clients: set secure httpOnly cookies
        if should_use_cookies(client_type):
            from app.config.settings import settings
            
            # Set session cookie (NOT the JWT access token)
            response.set_cookie(
                key=settings.SESSION_COOKIE_NAME,
                value=tokens["refresh_token"],  # Use refresh token as session identifier
                max_age=86400 * (30 if login_data.remember_me else 1),
                httponly=settings.SESSION_COOKIE_HTTPONLY,
                secure=settings.SESSION_COOKIE_SECURE,
                samesite=settings.SESSION_COOKIE_SAMESITE,
            )
            
            # Don't include tokens in response body for browsers
            response_tokens = None
        else:
            # For mobile/API clients: return tokens in response body
            response_tokens = TokenResponse(**tokens)
        
        return LoginResponse(
            success=True,
            message=f"Login successful ({client_type} client)",
            user=UserProfile(
                id=user.id,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                full_name=user.full_name,
                is_verified=user.is_verified,
                is_superuser=user.is_superuser,
                created_at=user.created_at,
                last_login_at=user.last_login_at,
            ),
            tokens=response_tokens,
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
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using refresh token."""
    
    auth_service = AuthService(db)
    
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
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = None,
    current_user: Optional[User] = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Logout user by revoking session."""
    
    auth_service = AuthService(db)
    from app.config.settings import settings
    
    # Try to get refresh token from cookie if not provided
    if not refresh_token:
        refresh_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    
    # If no refresh token and we have a current user from JWT, revoke their current session
    if not refresh_token and current_user:
        # Extract session_id from JWT access token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            access_token = auth_header.split(" ")[1]
            try:
                from app.services.jwt_service import JWTService
                jwt_service = JWTService()
                payload = jwt_service.decode_access_token(access_token)
                session_id = payload.get("session_id")
                
                if session_id:
                    # Revoke session by session_id
                    await auth_service.logout_session_by_id(session_id, current_user.id)
            except Exception:
                # If JWT decoding fails, ignore (token might be invalid anyway)
                pass
    elif refresh_token:
        # Traditional logout with refresh token (for browser clients)
        await auth_service.logout(refresh_token)
    
    # Clear cookies with correct names
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    
    return {
        "success": True,
        "message": "Logout successful",
    }


@router.post("/logout-all")
async def logout_all_sessions(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Logout user from all sessions."""
    
    auth_service = AuthService(db)
    
    revoked_count = await auth_service.logout_all_sessions(current_user.id)
    
    return {
        "success": True,
        "message": f"Logged out from {revoked_count} sessions",
        "revoked_sessions": revoked_count,
    }


@router.post("/password-reset/request")
async def request_password_reset(
    reset_request: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    """Request password reset token."""
    
    auth_service = AuthService(db)
    
    # Always return success to avoid email enumeration
    await auth_service.create_password_reset_token(reset_request.email)
    
    return {
        "success": True,
        "message": "If the email exists, a reset token has been sent",
    }


@router.post("/password-reset/confirm")
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirmRequest,
    db: AsyncSession = Depends(get_db),
):
    """Confirm password reset with token."""
    
    auth_service = AuthService(db)
    
    try:
        await auth_service.reset_password(reset_confirm.token, reset_confirm.new_password)
        
        return {
            "success": True,
            "message": "Password reset successful",
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )


@router.get("/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
):
    """Get current user information."""
    
    return {
        "success": True,
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "username": current_user.username,
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "is_verified": current_user.is_verified,
            "is_superuser": current_user.is_superuser,
            "created_at": current_user.created_at,
            "last_login_at": current_user.last_login_at,
        },
    }


@router.post("/verify-token")
async def verify_token(
    current_user: User = Depends(get_current_active_user),
):
    """Verify if current token is valid."""
    
    return {
        "success": True,
        "message": "Token is valid",
        "user_id": current_user.id,
    }


# ================== MOBILE/API CLIENT SPECIFIC ENDPOINTS ==================

@router.post("/mobile/login", response_model=LoginResponse)
async def mobile_login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Mobile client login - returns JWT tokens only, no cookies.
    
    For iOS/Android/Flutter applications that store tokens securely.
    """
    auth_service = AuthService(db)
    
    try:
        user = await auth_service.authenticate_user(
            email=login_data.email,
            password=login_data.password,
        )
        
        user_agent = request.headers.get("User-Agent")
        device_name, device_type = get_device_info(user_agent)
        
        tokens = await auth_service.create_user_session(
            user=user,
            user_agent=user_agent,
            ip_address=getattr(request.state, "client_ip", None),
            device_name=device_name or "Mobile Device",
            device_type="mobile",
            is_remember_me=login_data.remember_me,
        )
        
        from app.schemas.auth import UserProfile
        
        return {
            "success": True,
            "message": "Mobile login successful",
            "user": UserProfile.model_validate(user),
            "tokens": tokens,
            "device_info": {
                "device_name": device_name or "Mobile Device",
                "device_type": device_type or "mobile",
            },
        }
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/api-key/create")
async def create_api_key(
    name: str,
    scopes: Optional[list] = Query(default=None),
    expires_days: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Create API key for machine-to-machine authentication.
    
    API keys have format: pauth_xxx... and are stored as hashes.
    """
    
    from app.models.api_key import APIKey
    from app.utils.security import generate_api_key, hash_token, create_expiration_time
    
    # Generate API key
    api_key = generate_api_key(prefix="pauth", length=32)
    key_hash = hash_token(api_key)
    
    # Set expiration
    expires_at = None
    if expires_days:
        expires_at = create_expiration_time(days=expires_days)
    
    # Create API key record
    api_key_record = APIKey(
        user_id=current_user.id,
        name=name,
        key_hash=key_hash,
        prefix=api_key.split("_")[0],
        scopes_list=scopes or [],
        expires_at=expires_at,
    )
    
    db.add(api_key_record)
    await db.commit()
    await db.refresh(api_key_record)
    
    return {
        "success": True,
        "message": "API key created successfully",
        "api_key": api_key,  # Only returned once!
        "key_info": {
            "id": api_key_record.id,
            "name": api_key_record.name,
            "prefix": api_key_record.prefix,
            "scopes": api_key_record.scopes_list,
            "expires_at": api_key_record.expires_at,
            "created_at": api_key_record.created_at,
        },
        "warning": "Store this API key securely. It will not be shown again.",
    }


@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """List user's API keys (without the actual keys)."""
    
    from sqlalchemy import select
    from app.models.api_key import APIKey
    
    result = await db.execute(
        select(APIKey).where(
            APIKey.user_id == current_user.id,
            APIKey.is_active == True,
        ).order_by(APIKey.created_at.desc())
    )
    api_keys = result.scalars().all()
    
    return {
        "success": True,
        "api_keys": [
            {
                "id": key.id,
                "name": key.name,
                "prefix": key.prefix,
                "scopes": key.scopes_list,
                "is_valid": key.is_valid,
                "last_used_at": key.last_used_at,
                "usage_count": key.usage_count,
                "expires_at": key.expires_at,
                "created_at": key.created_at,
            }
            for key in api_keys
        ],
    }


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key."""
    
    from sqlalchemy import select
    from app.models.api_key import APIKey
    
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.user_id == current_user.id,
        )
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    
    api_key.revoke()
    await db.commit()
    
    return {
        "success": True,
        "message": "API key revoked successfully",
    }
