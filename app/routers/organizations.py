"""Organization management routes."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import get_current_active_user
from app.dependencies.database import get_db
from app.models.membership import Role
from app.models.user import User
from app.policies.base_policy import Action
from app.policies.guards import require
from app.schemas.organization import (
    MemberListResponse,
    MembershipResponse,
    OrganizationCreate,
    OrganizationDetailResponse,
    OrganizationListResponse,
    OrganizationResponse,
    OrganizationUpdate,
    OrganizationUpdateResponse,
    OrganizationWithRole,
)
from app.schemas.user import UserResponse
from app.services.organization_service import OrganizationService
from app.utils.exceptions import NotFoundError, ValidationError

router = APIRouter()


@router.get("/", response_model=OrganizationListResponse)
async def get_organizations(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """Get organizations user has access to."""

    org_service = OrganizationService(db)
    org_memberships, total = await org_service.get_user_organizations(
        user_id=current_user.id,
        page=page,
        per_page=per_page,
    )

    organizations_with_roles = [
        OrganizationWithRole(
            organization=org,
            role=membership.role,
            joined_at=membership.created_at,
        )
        for org, membership in org_memberships
    ]

    return OrganizationListResponse(
        success=True,
        message="Organizations retrieved successfully",
        organizations=organizations_with_roles,
        total=total,
    )


@router.post("/", response_model=OrganizationDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_create: OrganizationCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Create new organization."""

    org_service = OrganizationService(db)

    try:
        organization = await org_service.create_organization(
            name=org_create.name,
            slug=org_create.slug,
            user_id=current_user.id,
            description=org_create.description,
            website=org_create.website,
            email=org_create.email,
            phone=org_create.phone,
        )

        return OrganizationDetailResponse(
            success=True,
            message="Organization created successfully",
            organization=OrganizationResponse.model_validate(organization),
            user_role=Role.OWNER,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@router.get("/{organization_id}", response_model=OrganizationDetailResponse)
async def get_organization(
    organization_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get organization details."""

    # Check permissions
    require(
        user=current_user,
        action=Action.READ,
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
    )

    org_service = OrganizationService(db)

    organization = await org_service.get_organization_by_id(organization_id)
    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    user_role = await org_service.get_user_role_in_organization(
        user_id=current_user.id,
        organization_id=organization_id,
    )

    return OrganizationDetailResponse(
        success=True,
        message="Organization retrieved successfully",
        organization=OrganizationResponse.model_validate(organization),
        user_role=user_role,
    )


@router.put("/{organization_id}", response_model=OrganizationUpdateResponse)
async def update_organization(
    organization_id: int,
    org_update: OrganizationUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Update organization."""

    # Check permissions
    require(
        user=current_user,
        action=Action.UPDATE,
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
    )

    org_service = OrganizationService(db)

    try:
        update_data = org_update.dict(exclude_unset=True)
        organization = await org_service.update_organization(
            organization_id=organization_id,
            **update_data,
        )

        return OrganizationUpdateResponse(
            success=True,
            message="Organization updated successfully",
            organization={
                "id": organization.id,
                "name": organization.name,
                "updated_at": organization.updated_at,
            },
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )


@router.get("/{organization_id}/members", response_model=MemberListResponse)
async def get_organization_members(
    organization_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """Get organization members."""

    # Check permissions
    require(
        user=current_user,
        action=Action.READ,
        resource_type="organization",
        resource_id=organization_id,
        organization_id=organization_id,
    )

    org_service = OrganizationService(db)
    user_memberships, total = await org_service.get_organization_members(
        organization_id=organization_id,
        page=page,
        per_page=per_page,
    )

    members = [
        MembershipResponse(
            id=membership.id,
            user_id=user.id,
            organization_id=membership.organization_id,
            role=membership.role,
            is_active=membership.is_active,
            user=UserResponse.model_validate(user),
            created_at=membership.created_at,
            updated_at=membership.updated_at,
        )
        for user, membership in user_memberships
    ]

    return MemberListResponse(
        success=True,
        message="Organization members retrieved successfully",
        members=members,
        total=total,
        page=page,
        per_page=per_page,
    )
