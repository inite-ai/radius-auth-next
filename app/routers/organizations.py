"""Organization management routes."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.constants.status_codes import APIStatus
from app.decorators.permissions import (
    require_create_permission,
    require_organization_permission,
    validate_organization_exists,
)
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_organization_service
from app.models.user import User
from app.policies.base_policy import Action
from app.schemas.organization import (
    MemberAddRequest,
    MemberListResponse,
    MembershipResponse,
    OrganizationCreate,
    OrganizationDetailResponse,
    OrganizationListResponse,
    OrganizationUpdate,
    OrganizationUpdateResponse,
    OrganizationWithRole,
)
from app.schemas.user import UserResponse
from app.services.organization_service import OrganizationService
from app.utils.exceptions import NotFoundError, ValidationError
from app.utils.response_builders import ResponseBuilder

router = APIRouter()


@router.get("/", response_model=OrganizationListResponse)
async def get_organizations(
    current_user: User = Depends(get_current_active_user),
    org_service: OrganizationService = Depends(get_organization_service),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """Get organizations user has access to."""
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

    return ResponseBuilder.organization_list(organizations_with_roles, total)


@router.post("/", response_model=OrganizationDetailResponse, status_code=APIStatus.CREATED)
@require_create_permission("organization")
async def create_organization(
    org_create: OrganizationCreate,
    current_user: User = Depends(get_current_active_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    """Create new organization."""

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

        return ResponseBuilder.organization_created(organization, "owner")
    except ValidationError as e:
        raise HTTPException(
            status_code=APIStatus.CONFLICT,
            detail=str(e),
        )


@router.get("/{organization_id}", response_model=OrganizationDetailResponse)
@validate_organization_exists()
@require_organization_permission(Action.READ)
async def get_organization(
    organization_id: int,
    current_user: User = Depends(get_current_active_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    """Get organization details."""

    organization = await org_service.get_organization_by_id(organization_id)
    if not organization:
        raise HTTPException(
            status_code=APIStatus.NOT_FOUND,
            detail="Organization not found",
        )

    user_role = await org_service.get_user_role_in_organization(
        user_id=current_user.id,
        organization_id=organization_id,
    )

    return ResponseBuilder.organization_detail(organization, user_role)


@router.put("/{organization_id}", response_model=OrganizationUpdateResponse)
@validate_organization_exists()
@require_organization_permission(Action.UPDATE)
async def update_organization(
    organization_id: int,
    org_update: OrganizationUpdate,
    current_user: User = Depends(get_current_active_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    """Update organization."""

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
            status_code=APIStatus.NOT_FOUND,
            detail="Organization not found",
        )


@router.get("/{organization_id}/members", response_model=MemberListResponse)
@validate_organization_exists()
@require_organization_permission(Action.READ)
async def get_organization_members(
    organization_id: int,
    current_user: User = Depends(get_current_active_user),
    org_service: OrganizationService = Depends(get_organization_service),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """Get organization members."""
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


@router.post("/{organization_id}/members", status_code=APIStatus.CREATED)
@validate_organization_exists()
@require_organization_permission(Action.MANAGE)
async def add_organization_member(
    organization_id: int,
    member_request: MemberAddRequest,
    current_user: User = Depends(get_current_active_user),
    org_service: OrganizationService = Depends(get_organization_service),
):
    """Add a member to organization."""
    from app.models.membership import Role

    try:
        membership = await org_service.add_member(
            organization_id=organization_id,
            user_id=member_request.user_id,
            role=Role(member_request.role),
        )
        return ResponseBuilder.success(
            "Member added successfully",
            membership_id=membership.id,
            user_id=membership.user_id,
            role=membership.role,
        )
    except ValidationError as e:
        raise HTTPException(status_code=APIStatus.CONFLICT, detail=str(e))
    except NotFoundError as e:
        raise HTTPException(status_code=APIStatus.NOT_FOUND, detail=str(e))
