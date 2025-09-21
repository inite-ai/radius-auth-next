"""Organization management routes."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import get_current_active_user
from app.dependencies.database import get_db
from app.models.membership import Membership, Role
from app.models.organization import Organization
from app.models.user import User
from app.policies.base_policy import Action
from app.policies.guards import require
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationDetailResponse,
    OrganizationListResponse,
    OrganizationResponse,
    OrganizationWithRole,
)

router = APIRouter()


@router.get("/", response_model=OrganizationListResponse)
async def get_organizations(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
):
    """Get organizations user has access to."""

    # Get user's organizations through memberships
    result = await db.execute(
        select(Organization, Membership)
        .join(Membership, Organization.id == Membership.organization_id)
        .where(
            Membership.user_id == current_user.id,
            Membership.is_active,
            Organization.is_active,
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
    )

    org_memberships = result.all()

    organizations_with_roles = []
    for org, membership in org_memberships:
        organizations_with_roles.append(
            OrganizationWithRole(
                organization=org,
                role=membership.role,
                joined_at=membership.created_at,
            )
        )

    return OrganizationListResponse(
        success=True,
        message="Organizations retrieved successfully",
        organizations=organizations_with_roles,
        total=len(organizations_with_roles),
    )


@router.post("/", response_model=OrganizationDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    org_create: OrganizationCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Create new organization."""

    # Check if slug is already taken
    result = await db.execute(select(Organization).where(Organization.slug == org_create.slug))
    existing_org = result.scalar_one_or_none()

    if existing_org:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization slug already exists",
        )

    # Create organization
    organization = Organization(**org_create.dict())

    db.add(organization)
    await db.flush()  # Get the ID

    # Create owner membership for current user
    membership = Membership(
        user_id=current_user.id,
        organization_id=organization.id,
        role=Role.OWNER,
        is_active=True,
    )

    db.add(membership)
    await db.commit()
    await db.refresh(organization)

    return OrganizationDetailResponse(
        success=True,
        message="Organization created successfully",
        organization=OrganizationResponse.model_validate(organization),
        user_role=Role.OWNER,
    )


@router.get("/{organization_id}")
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

    # Get organization
    result = await db.execute(
        select(Organization).where(
            Organization.id == organization_id,
            Organization.is_active,
        )
    )
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Get user's role in organization
    membership_result = await db.execute(
        select(Membership).where(
            Membership.user_id == current_user.id,
            Membership.organization_id == organization_id,
            Membership.is_active,
        )
    )
    membership = membership_result.scalar_one_or_none()

    return {
        "success": True,
        "organization": {
            "id": organization.id,
            "name": organization.name,
            "slug": organization.slug,
            "description": organization.description,
            "is_personal": organization.is_personal,
            "website": organization.website,
            "email": organization.email,
            "phone": organization.phone,
            "logo_url": organization.logo_url,
            "primary_color": organization.primary_color,
            "plan": organization.plan,
            "max_users": organization.max_users,
            "user_count": organization.user_count,
            "role": membership.role if membership else None,
            "created_at": organization.created_at,
            "updated_at": organization.updated_at,
        },
    }


@router.put("/{organization_id}")
async def update_organization(
    organization_id: int,
    name: str | None = None,
    description: str | None = None,
    website: str | None = None,
    email: str | None = None,
    phone: str | None = None,
    logo_url: str | None = None,
    primary_color: str | None = None,
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

    # Get organization
    result = await db.execute(select(Organization).where(Organization.id == organization_id))
    organization = result.scalar_one_or_none()

    if not organization:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # Update fields
    if name is not None:
        organization.name = name
    if description is not None:
        organization.description = description
    if website is not None:
        organization.website = website
    if email is not None:
        organization.email = email
    if phone is not None:
        organization.phone = phone
    if logo_url is not None:
        organization.logo_url = logo_url
    if primary_color is not None:
        organization.primary_color = primary_color

    await db.commit()
    await db.refresh(organization)

    return {
        "success": True,
        "message": "Organization updated successfully",
        "organization": {
            "id": organization.id,
            "name": organization.name,
            "updated_at": organization.updated_at,
        },
    }


@router.get("/{organization_id}/members")
async def get_organization_members(
    organization_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
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

    # Get members
    result = await db.execute(
        select(User, Membership)
        .join(Membership, User.id == Membership.user_id)
        .where(
            Membership.organization_id == organization_id,
            Membership.is_active,
            User.is_active,
        )
        .offset(skip)
        .limit(limit)
    )

    user_memberships = result.all()

    return {
        "success": True,
        "members": [
            {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "role": membership.role,
                "joined_at": membership.created_at,
                "last_login_at": user.last_login_at,
            }
            for user, membership in user_memberships
        ],
        "pagination": {
            "skip": skip,
            "limit": limit,
            "total": len(user_memberships),
        },
    }
