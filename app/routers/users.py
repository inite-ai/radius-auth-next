"""User management routes."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies.auth import get_current_active_user, get_current_organization
from app.dependencies.database import get_db
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

router = APIRouter()


@router.post("/", response_model=UserDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_create: UserCreate,
    organization: Organization | None = Depends(get_current_organization),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Create new user."""

    # Check permissions
    require(
        user=current_user,
        action=Action.CREATE,
        resource_type="user",
        organization_id=organization.id if organization else None,
    )

    # Check if email already exists
    result = await db.execute(select(User).where(User.email == user_create.email))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Create user
    from app.utils.security import hash_password

    user_data = user_create.dict(exclude={"password"})
    user_data["password_hash"] = hash_password(user_create.password)

    user = User(**user_data)
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return UserDetailResponse(
        success=True,
        message="User created successfully",
        user=UserResponse.model_validate(user),
    )


@router.get("/", response_model=UserListResponse)
async def get_users(
    organization: Organization | None = Depends(get_current_organization),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
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

    # Build query
    query = select(User).where(User.is_active)

    # Filter by organization if specified
    if organization:
        # Join with memberships to filter by organization
        from app.models.membership import Membership

        query = query.join(Membership).where(
            Membership.organization_id == organization.id,
            Membership.is_active,
        )

    # Add search filter
    if search:
        search_term = f"%{search}%"
        query = query.where(
            User.first_name.ilike(search_term)
            | User.last_name.ilike(search_term)
            | User.email.ilike(search_term)
        )

    # Count total for pagination
    count_result = await db.execute(query)
    total = len(count_result.scalars().all())

    # Apply pagination
    skip = (page - 1) * per_page
    query = query.offset(skip).limit(per_page)

    result = await db.execute(query)
    users = result.scalars().all()

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
    db: AsyncSession = Depends(get_db),
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

    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

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
    db: AsyncSession = Depends(get_db),
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

    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update fields
    update_data = user_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    await db.commit()
    await db.refresh(user)

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
    db: AsyncSession = Depends(get_db),
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

    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Deactivate user instead of hard delete
    user.is_active = False
    await db.commit()

    return {
        "success": True,
        "message": "User deactivated successfully",
    }


@router.post("/change-password")
async def change_password(
    password_change: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Change current user's password."""

    from app.utils.security import hash_password, verify_password

    # Verify current password
    if not verify_password(password_change.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Update password
    current_user.password_hash = hash_password(password_change.new_password)
    current_user.password_changed_at = datetime.utcnow()

    # Revoke all sessions to force re-login
    from app.services.session_service import SessionService

    session_service = SessionService(db)
    await session_service.revoke_all_user_sessions(current_user.id)

    await db.commit()

    return {
        "success": True,
        "message": "Password changed successfully. Please log in again.",
    }
