"""User management service."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.membership import Membership
from app.models.user import User
from app.utils.exceptions import NotFoundError, ValidationError
from app.utils.security import hash_password


class UserService:
    """Service for user management operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        username: str | None = None,
        middle_name: str | None = None,
        phone: str | None = None,
        avatar_url: str | None = None,
        timezone: str | None = None,
        locale: str | None = None,
        bio: str | None = None,
        is_verified: bool = False,
        is_superuser: bool = False,
    ) -> User:
        """Create a new user."""

        # Check if email already exists
        result = await self.db.execute(select(User).where(User.email == email))
        existing_user = result.scalar_one_or_none()

        if existing_user:
            raise ValidationError("Email already registered")

        # Create user
        password_hash = hash_password(password)

        user = User(
            email=email,
            username=username,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            password_hash=password_hash,
            phone=phone,
            avatar_url=avatar_url,
            timezone=timezone,
            locale=locale,
            bio=bio,
            is_verified=is_verified,
            is_superuser=is_superuser,
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def get_users(
        self,
        organization_id: int | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[list[User], int]:
        """Get users list with pagination and filtering."""

        # Build query
        query = select(User).where(User.is_active)

        # Filter by organization if specified
        if organization_id:
            query = query.join(Membership, User.id == Membership.user_id).where(
                Membership.organization_id == organization_id,
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
        count_result = await self.db.execute(query)
        total = len(count_result.scalars().all())

        # Apply pagination and order
        query = query.order_by(User.created_at.desc()).offset(skip).limit(limit)

        # Execute query
        result = await self.db.execute(query)
        users = result.scalars().all()

        return list(users), total

    async def get_user_by_id(self, user_id: int) -> User:
        """Get user by ID."""

        result = await self.db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            raise NotFoundError("User not found")

        return user

    async def update_user(self, user_id: int, **update_data) -> User:
        """Update user."""

        user = await self.get_user_by_id(user_id)

        # Update fields
        for field, value in update_data.items():
            if hasattr(user, field) and value is not None:
                setattr(user, field, value)

        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def delete_user(self, user_id: int) -> bool:
        """Soft delete user."""

        user = await self.get_user_by_id(user_id)
        user.is_active = False

        await self.db.commit()
        return True

    async def change_password(self, user_id: int, current_password: str, new_password: str) -> User:
        """Change user password with verification and revoke all sessions atomically."""

        from datetime import datetime

        from app.utils.security import hash_password, verify_password
        from app.utils.transaction_manager import atomic_operation

        async with atomic_operation(self.db):
            user = await self.get_user_by_id(user_id)

            # Verify current password
            if not verify_password(current_password, user.password_hash):
                raise ValidationError("Current password is incorrect")

            # Update password
            user.password_hash = hash_password(new_password)
            user.password_changed_at = datetime.utcnow()

            # Revoke all sessions as part of the same transaction for security
            from app.services.session_service import SessionService

            session_service = SessionService(self.db)
            await session_service.revoke_all_user_sessions(user_id)

        await self.db.refresh(user)
        return user

    async def verify_email(self, user_id: int) -> User:
        """Verify user email."""

        user = await self.get_user_by_id(user_id)
        user.is_verified = True
        user.verification_token = None
        user.verification_token_expires_at = None

        # Set email verified timestamp
        from datetime import datetime

        user.email_verified_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(user)

        return user
