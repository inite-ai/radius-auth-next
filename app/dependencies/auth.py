"""Authentication dependencies for FastAPI."""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services.auth_service import AuthService
from app.utils.exceptions import InvalidTokenError

from .database import get_db

# Security scheme for Bearer tokens
security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Get current user from token or session."""

    auth_service = AuthService(db)

    # Try Bearer token first (for API clients and OAuth)
    if credentials:
        try:
            # First try as our internal JWT
            payload = await auth_service.verify_access_token(credentials.credentials)
            user_id = int(payload["sub"])

            result = await db.execute(
                select(User).options(selectinload(User.memberships)).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()

            if user and user.can_login:
                # Check session status if session_id is in payload
                if "session_id" in payload:
                    from app.models.session import Session

                    session_result = await db.execute(
                        select(Session).where(
                            Session.id == payload["session_id"],
                            Session.user_id == user.id,
                            Session.is_active == True,
                            Session.is_revoked == False,
                        )
                    )
                    session = session_result.scalar_one_or_none()
                    if not session:
                        # Session is revoked or invalid
                        return None

                # Store organization_id from token in request state
                if "org_id" in payload:
                    request.state.organization_id = payload["org_id"]
                return user

        except InvalidTokenError:
            # Try as OAuth access token
            try:
                from app.services.oauth_service import OAuthService

                oauth_service = OAuthService(db)
                token_user = await oauth_service.validate_access_token(credentials.credentials)

                if token_user:
                    token, user = token_user
                    # Store OAuth token info in request state
                    request.state.oauth_token = token
                    request.state.oauth_scopes = token.scopes_list
                    return user

            except Exception:
                pass
        except Exception:
            # Catch any other JWT related errors
            pass

    # Try session cookie (for browser clients)
    from app.config.settings import settings

    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_token:
        try:
            # Session token is actually the refresh token for browsers
            session = await auth_service.session_service.get_session_by_refresh_token(session_token)
            if session:
                try:
                    is_valid = await auth_service.session_service.validate_session(session)
                    if is_valid:
                        # Update session activity
                        ip_address = getattr(request.state, "client_ip", None)
                        await auth_service.session_service.update_session_activity(
                            session, ip_address
                        )
                        return session.user
                except Exception:
                    pass
        except Exception:
            pass

    # Try API key (for machine clients)
    api_key = request.headers.get("X-API-Key")
    if api_key:
        try:
            user, _ = await auth_service.authenticate_api_key(api_key)
            return user
        except Exception:
            pass

    return None


async def get_current_active_user(
    current_user: User | None = Depends(get_current_user),
) -> User:
    """Get current active user, raise exception if not authenticated."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not current_user.can_login:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive or locked",
        )

    return current_user


async def get_optional_current_user(
    current_user: User | None = Depends(get_current_user),
) -> User | None:
    """Get current user if authenticated, otherwise None."""
    return current_user


async def get_current_organization(
    request: Request,
    organization_id: int | None = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Organization | None:
    """Get current organization from parameter or token."""

    # Try organization_id parameter first
    target_org_id = organization_id

    # Fall back to organization_id from token/request state
    if not target_org_id:
        target_org_id = getattr(request.state, "organization_id", None)

    # Fall back to organization_id from query params or path
    if not target_org_id:
        target_org_id = request.path_params.get("organization_id")
        if not target_org_id:
            target_org_id = request.query_params.get("organization_id")

        if target_org_id:
            try:
                target_org_id = int(target_org_id)
            except ValueError:
                target_org_id = None

    if not target_org_id:
        return None

    # Get organization and verify user has access
    result = await db.execute(select(Organization).where(Organization.id == target_org_id))
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Check if user has access to organization
    membership_result = await db.execute(
        select(Membership).where(
            Membership.user_id == current_user.id,
            Membership.organization_id == organization.id,
            Membership.is_active == True,
        )
    )
    membership = membership_result.scalar_one_or_none()

    if not membership and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No access to this organization",
        )

    return organization


async def require_superuser(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Require superuser access."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )
    return current_user
