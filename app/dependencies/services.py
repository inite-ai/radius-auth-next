"""Service dependency injection."""

from collections.abc import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.database import get_db
from app.services.auth_service import AuthService
from app.services.oauth_service import OAuthService
from app.services.organization_service import OrganizationService
from app.services.session_service import SessionService
from app.services.user_service import UserService


async def get_auth_service(db: AsyncSession = Depends(get_db)) -> AsyncGenerator[AuthService, None]:
    """Get AuthService instance."""
    yield AuthService(db)


async def get_user_service(db: AsyncSession = Depends(get_db)) -> AsyncGenerator[UserService, None]:
    """Get UserService instance."""
    yield UserService(db)


async def get_organization_service(
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[OrganizationService, None]:
    """Get OrganizationService instance."""
    yield OrganizationService(db)


async def get_oauth_service(
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[OAuthService, None]:
    """Get OAuthService instance."""
    yield OAuthService(db)


async def get_session_service(
    db: AsyncSession = Depends(get_db),
) -> AsyncGenerator[SessionService, None]:
    """Get SessionService instance."""
    yield SessionService(db)


async def get_organization_by_id(
    organization_id: int,
    org_service: OrganizationService = Depends(get_organization_service),
):
    """Get organization by ID."""
    from fastapi import HTTPException

    from app.constants.status_codes import APIStatus

    organization = await org_service.get_organization_by_id(organization_id)
    if not organization:
        raise HTTPException(
            status_code=APIStatus.NOT_FOUND,
            detail="Organization not found",
        )
    return organization
