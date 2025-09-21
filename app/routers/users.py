"""User management routes."""


from fastapi import APIRouter, Depends, Query

from app.constants.status_codes import APIStatus
from app.decorators.permissions import (
    require_create_permission,
    require_read_permission,
    require_user_permission,
    validate_user_exists,
)
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_user_service
from app.models.user import User
from app.policies.base_policy import Action
from app.schemas.user import (
    PasswordChangeRequest,
    UserCreate,
    UserDetailResponse,
    UserListResponse,
    UserUpdate,
)
from app.services.user_service import UserService
from app.utils.response_builders import ResponseBuilder

router = APIRouter()


@router.post("/", response_model=UserDetailResponse, status_code=APIStatus.CREATED)
@require_create_permission("user")
async def create_user(
    user_create: UserCreate,
    organization_id: int | None = Query(None, description="Organization ID"),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Create new user."""

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

    return ResponseBuilder.user_created(user)


@router.get("/", response_model=UserListResponse)
@require_read_permission("user")
async def get_users(
    organization_id: int | None = Query(None, description="Organization ID"),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    search: str | None = Query(None, max_length=100, description="Search query"),
):
    """Get users list."""

    skip = (page - 1) * per_page
    users, total = await user_service.get_users(
        organization_id=organization_id,
        search=search,
        skip=skip,
        limit=per_page,
    )

    return ResponseBuilder.user_list(users, total, page, per_page)


@router.get("/profile", response_model=UserDetailResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user),
):
    """Get current user profile."""
    return ResponseBuilder.user_detail(current_user, "User profile retrieved successfully")


@router.get("/{user_id}", response_model=UserDetailResponse)
@require_user_permission(Action.READ)
@validate_user_exists()
async def get_user(
    user_id: int,
    organization_id: int | None = Query(None, description="Organization ID"),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Get user by ID."""

    user = await user_service.get_user_by_id(user_id)

    return ResponseBuilder.user_detail(user)


@router.put("/{user_id}", response_model=UserDetailResponse)
@require_user_permission(Action.UPDATE)
@validate_user_exists()
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    organization_id: int | None = Query(None, description="Organization ID"),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Update user information."""

    user = await user_service.update_user(user_id, **user_update.dict(exclude_unset=True))

    return ResponseBuilder.user_updated(user)


@router.delete("/{user_id}")
@require_user_permission(Action.DELETE)
@validate_user_exists()
async def delete_user(
    user_id: int,
    organization_id: int | None = Query(None, description="Organization ID"),
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Delete (deactivate) user."""

    await user_service.delete_user(user_id)

    return ResponseBuilder.resource_deactivated("user")


@router.post("/change-password")
async def change_password(
    password_change: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
):
    """Change current user's password."""

    # Change password (includes verification and session revocation atomically)
    await user_service.change_password(
        user_id=current_user.id,
        current_password=password_change.current_password,
        new_password=password_change.new_password,
    )

    return ResponseBuilder.password_changed()
