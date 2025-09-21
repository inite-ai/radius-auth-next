"""User management routes."""


from fastapi import APIRouter, Depends, Query, status

from app.dependencies.auth import get_current_active_user, get_current_organization
from app.dependencies.services import get_user_service
from app.models.organization import Organization
from app.models.user import User
from app.policies.base_policy import Action
from app.policies.guards import require
from app.schemas.user import (
    PasswordChangeRequest,
    UserCreate,
    UserDetailResponse,
    UserListResponse,
    UserResponse,
    UserUpdate,
)
from app.services.user_service import UserService

router = APIRouter()


@router.post("/", response_model=UserDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_create: UserCreate,
    organization: Organization | None = Depends(get_current_organization),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Create new user."""

    # Check permissions
    require(
        user=current_user,
        action=Action.CREATE,
        resource_type="user",
        organization_id=organization.id if organization else None,
    )

    user = await user_service.create_user(
        email=user_create.email,
        password=user_create.password,
        first_name=user_create.first_name,
        last_name=user_create.last_name,
        username=user_create.username,
        middle_name=user_create.middle_name,
        phone=user_create.phone,
        avatar_url=user_create.avatar_url,
        timezone=user_create.timezone,
        locale=user_create.locale,
        bio=user_create.bio,
    )

    return UserDetailResponse(
        success=True,
        message="User created successfully",
        user=UserResponse.model_validate(user),
    )


@router.get("/", response_model=UserListResponse)
async def get_users(
    organization: Organization | None = Depends(get_current_organization),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    search: str | None = Query(None, max_length=100, description="Search query"),
):
    """Get users list."""

    # Check permissions
    require(
        user=current_user,
        action=Action.READ,
        resource_type="user",
        organization_id=organization.id if organization else None,
    )

    skip = (page - 1) * per_page
    users, total = await user_service.get_users(
        organization_id=organization.id if organization else None,
        search=search,
        skip=skip,
        limit=per_page,
    )

    return UserListResponse(
        success=True,
        message="Users retrieved successfully",
        users=[UserResponse.model_validate(user) for user in users],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/profile", response_model=UserDetailResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user),
):
    """Get current user profile."""
    return UserDetailResponse(
        success=True,
        message="User profile retrieved successfully",
        user=UserResponse.model_validate(current_user),
    )


@router.get("/{user_id}", response_model=UserDetailResponse)
async def get_user(
    user_id: int,
    organization: Organization | None = Depends(get_current_organization),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Get user by ID."""

    # Check permissions
    require(
        user=current_user,
        action=Action.READ,
        resource_type="user",
        resource_id=user_id,
        organization_id=organization.id if organization else None,
    )

    user = await user_service.get_user_by_id(user_id)

    return UserDetailResponse(
        success=True,
        message="User retrieved successfully",
        user=UserResponse.model_validate(user),
    )


@router.put("/{user_id}", response_model=UserDetailResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    organization: Organization | None = Depends(get_current_organization),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Update user information."""

    # Check permissions
    require(
        user=current_user,
        action=Action.UPDATE,
        resource_type="user",
        resource_id=user_id,
        organization_id=organization.id if organization else None,
    )

    user = await user_service.update_user(user_id, **user_update.dict(exclude_unset=True))

    return UserDetailResponse(
        success=True,
        message="User updated successfully",
        user=UserResponse.model_validate(user),
    )


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    organization: Organization | None = Depends(get_current_organization),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Delete (deactivate) user."""

    # Check permissions
    require(
        user=current_user,
        action=Action.DELETE,
        resource_type="user",
        resource_id=user_id,
        organization_id=organization.id if organization else None,
    )

    await user_service.delete_user(user_id)

    return {
        "success": True,
        "message": "User deactivated successfully",
    }


@router.post("/change-password")
async def change_password(
    password_change: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Change current user's password."""

    # Change password (includes verification)
    await user_service.change_password(
        user_id=current_user.id,
        current_password=password_change.current_password,
        new_password=password_change.new_password,
    )

    # Revoke all sessions to force re-login for security
    await user_service.revoke_all_user_sessions_on_password_change(current_user.id)

    return {
        "success": True,
        "message": "Password changed successfully. Please log in again.",
    }
