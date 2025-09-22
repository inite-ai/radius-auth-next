"""Authentication service with support for multiple auth strategies."""

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import settings
from app.models.api_key import APIKey
from app.models.membership import Membership
from app.models.user import User
from app.schemas.auth import APIKeyResponse, LoginResponse, TokenResponse, UserProfile
from app.utils.exceptions import (
    AccountLockedError,
    AuthenticationError,
    InvalidTokenError,
    UserNotFoundError,
)
from app.utils.security import (
    generate_random_string,
    hash_password,
    hash_token,
    verify_password,
)

from .jwt_service import JWTService
from .session_service import SessionService


class AuthService:
    """Authentication service supporting multiple auth strategies."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.jwt_service = JWTService()
        self.session_service = SessionService(db)

    async def register_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        username: str | None = None,
        middle_name: str | None = None,
        phone: str | None = None,
        timezone: str | None = None,
        locale: str | None = None,
        bio: str | None = None,
    ) -> User:
        """Register a new user."""
        from app.utils.exceptions import ValidationError

        # Check if user already exists
        result = await self.db.execute(select(User).where(User.email == email))
        existing_user = result.scalar_one_or_none()

        if existing_user:
            raise ValidationError("User with this email already exists")

        # Check username uniqueness if provided
        if username:
            result = await self.db.execute(select(User).where(User.username == username))
            existing_username = result.scalar_one_or_none()

            if existing_username:
                raise ValidationError("Username already taken")

        # Create new user
        user = User(
            email=email,
            password_hash=hash_password(password),
            first_name=first_name,
            last_name=last_name,
            username=username,
            middle_name=middle_name,
            phone=phone,
            timezone=timezone,
            locale=locale,
            bio=bio,
            is_verified=False,  # Users need to verify email
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def authenticate_user(
        self,
        email: str,
        password: str,
    ) -> User:
        """Authenticate user with email and password."""

        # Get user by email
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            raise UserNotFoundError("Invalid email or password")

        # Check if account is locked
        if user.is_locked:
            raise AccountLockedError(
                f"Account is locked until {user.locked_until}",
                details={"locked_until": user.locked_until},
            )

        # Verify password
        if not verify_password(password, user.password_hash):
            await self._handle_failed_login(user)
            raise AuthenticationError("Invalid email or password")

        # Check if user can login
        if not user.can_login:
            raise AuthenticationError("Account is inactive or unverified")

        # Reset failed login attempts on successful login
        await self._reset_failed_attempts(user)

        return user

    async def authenticate_api_key(self, api_key: str) -> tuple[User, APIKey]:
        """Authenticate using API key."""

        # Extract prefix and hash
        if "_" not in api_key:
            raise InvalidTokenError("Invalid API key format")

        prefix = api_key.split("_")[0]
        key_hash = hash_token(api_key)

        # Find API key with user
        result = await self.db.execute(
            select(APIKey)
            .join(User)
            .where(
                APIKey.key_hash == key_hash,
                APIKey.prefix == prefix,
                APIKey.is_active,
            )
        )
        api_key_obj = result.scalar_one_or_none()

        if not api_key_obj or not api_key_obj.is_valid:
            raise InvalidTokenError("Invalid or expired API key")

        # Load user relationship
        await self.db.refresh(api_key_obj, ["user"])

        # Record usage
        api_key_obj.record_usage()
        await self.db.commit()

        return api_key_obj.user, api_key_obj

    async def create_api_key(
        self,
        user_id: int,
        name: str,
        scopes: list[str] | None = None,
        expires_days: int | None = None,
    ) -> tuple[str, APIKey]:
        """Create a new API key for user."""

        from app.utils.security import create_expiration_time, generate_api_key, hash_token

        # Generate API key
        api_key = generate_api_key(prefix="pauth", length=32)
        key_hash = hash_token(api_key)

        # Set expiration if provided
        expires_at = None
        if expires_days:
            expires_at = create_expiration_time(days=expires_days)

        # Create API key record
        api_key_obj = APIKey(
            user_id=user_id,
            name=name,
            prefix=api_key.split("_")[0],
            key_hash=key_hash,
            scopes_list=scopes or [],
            expires_at=expires_at,
        )

        self.db.add(api_key_obj)
        await self.db.commit()
        await self.db.refresh(api_key_obj)

        return api_key, api_key_obj

    async def list_api_keys(self, user_id: int) -> list[APIKey]:
        """List user's API keys."""

        from sqlalchemy import select

        result = await self.db.execute(
            select(APIKey)
            .where(
                APIKey.user_id == user_id,
                APIKey.is_active,
            )
            .order_by(APIKey.created_at.desc())
        )
        return list(result.scalars().all())

    async def revoke_api_key(self, user_id: int, key_id: int) -> bool:
        """Revoke user's API key."""

        from sqlalchemy import select

        result = await self.db.execute(
            select(APIKey).where(
                APIKey.id == key_id,
                APIKey.user_id == user_id,
                APIKey.is_active,
            )
        )
        api_key = result.scalar_one_or_none()

        if not api_key:
            return False

        api_key.is_active = False
        await self.db.commit()

        return True

    async def create_user_session(
        self,
        user: User,
        user_agent: str | None = None,
        ip_address: str | None = None,
        device_name: str | None = None,
        device_type: str = "web",
        is_remember_me: bool = False,
        organization_id: int | None = None,
    ) -> dict[str, str]:
        """Create user session and return tokens."""

        # Create refresh token
        refresh_token = generate_random_string(64)

        # Create session
        session = await self.session_service.create_session(
            user=user,
            refresh_token=refresh_token,
            user_agent=user_agent,
            ip_address=ip_address,
            device_name=device_name,
            device_type=device_type,
            is_remember_me=is_remember_me,
        )

        # Create access token
        access_token = self.jwt_service.create_access_token(
            user_id=user.id,
            email=user.email,
            organization_id=organization_id,
            session_id=session.id,
        )

        # Update user last login
        user.last_login_at = datetime.utcnow()
        await self.db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    async def refresh_tokens(
        self,
        refresh_token: str,
        organization_id: int | None = None,
    ) -> dict[str, str]:
        """Refresh access and refresh tokens."""

        # Try to get session by refresh token directly first (for mobile sessions)
        session = await self.session_service.get_session_by_refresh_token(refresh_token)

        # If not found, try to decode as JWT refresh token (for web/OAuth sessions)
        if not session:
            try:
                payload = self.jwt_service.decode_refresh_token(refresh_token)
                session_id = payload["session_id"]
                # Try to find session by session_id from JWT
                session = await self.session_service.get_session_by_id(session_id)
            except Exception as e:
                raise InvalidTokenError(f"Invalid refresh token: {e}")

        if not session:
            raise InvalidTokenError("Session not found or expired")

        # Validate session
        if not await self.session_service.validate_session(session):
            raise InvalidTokenError("Invalid or expired session")

        # Generate new tokens
        new_refresh_token = generate_random_string(64)

        # Rotate refresh token (create new session, revoke old)
        new_session = await self.session_service.refresh_session(session, new_refresh_token)

        # Create new access token
        access_token = self.jwt_service.create_access_token(
            user_id=session.user.id,
            email=session.user.email,
            organization_id=organization_id,
            session_id=new_session.id,
        )

        # Update session activity
        await self.session_service.update_session_activity(new_session)

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_token,
            "token_type": "Bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    async def logout(self, refresh_token: str) -> None:
        """Logout user by revoking session."""
        session = await self.session_service.get_session_by_refresh_token(refresh_token)
        if session:
            await self.session_service.revoke_session(session)

    async def logout_session_by_id(self, session_id: int, user_id: int) -> None:
        """Logout user by revoking session by session_id (primary key)."""
        session = await self.session_service.get_session_by_id(session_id, user_id)
        if session:
            await self.session_service.revoke_session(session)

    async def logout_all_sessions(self, user_id: int) -> int:
        """Logout user from all sessions."""
        return await self.session_service.revoke_all_user_sessions(user_id)

    async def logout_other_sessions(self, user_id: int, current_refresh_token: str) -> int:
        """Logout user from all other sessions."""
        session = await self.session_service.get_session_by_refresh_token(current_refresh_token)
        if not session:
            return 0

        return await self.session_service.revoke_other_sessions(user_id, session.session_id)

    async def verify_access_token(self, token: str) -> dict[str, any]:
        """Verify access token and return payload."""
        try:
            payload = self.jwt_service.decode_access_token(token)

            # Verify user still exists and is active
            user_id = int(payload["sub"])
            result = await self.db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()

            if not user or not user.can_login:
                raise InvalidTokenError("User not found or inactive")

            return payload

        except Exception as e:
            raise InvalidTokenError(f"Token validation failed: {e}")

    async def create_password_reset_token(self, email: str) -> str:
        """Create password reset token."""
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            # Don't reveal if email exists
            return ""

        token = self.jwt_service.create_password_reset_token(user.id, user.email)

        # Store token in user record
        user.reset_token = hash_token(token)
        user.reset_token_expires_at = datetime.utcnow() + timedelta(hours=1)
        await self.db.commit()

        return token

    async def reset_password(self, token: str, new_password: str) -> None:
        """Reset user password with token."""
        from app.utils.transaction_manager import atomic_operation

        try:
            payload = self.jwt_service.decode_token(token)
            if payload.get("type") != "password_reset":
                raise InvalidTokenError("Invalid token type")

            user_id = int(payload["sub"])
            email = payload["email"]

        except Exception as e:
            raise InvalidTokenError(f"Invalid reset token: {e}")

        async with atomic_operation(self.db):
            # Get user and verify token
            result = await self.db.execute(
                select(User).where(User.id == user_id, User.email == email)
            )
            user = result.scalar_one_or_none()

            if not user or not user.reset_token:
                raise InvalidTokenError("Invalid or expired token")

            # Verify stored token hash
            if not hash_token(token) == user.reset_token:
                raise InvalidTokenError("Invalid token")

            # Check expiration
            if user.reset_token_expires_at and user.reset_token_expires_at < datetime.utcnow():
                raise InvalidTokenError("Token expired")

            # Update password atomically with session revocation
            user.password_hash = hash_password(new_password)
            user.password_changed_at = datetime.utcnow()
            user.reset_token = None
            user.reset_token_expires_at = None

            # Revoke all sessions (force re-login) - part of the same transaction
            await self.session_service.revoke_all_user_sessions(user.id)

    async def _handle_failed_login(self, user: User) -> None:
        """Handle failed login attempt."""
        user.failed_login_attempts += 1

        # Lock account after max attempts
        if user.failed_login_attempts >= settings.ACCOUNT_LOCKOUT_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(
                minutes=settings.ACCOUNT_LOCKOUT_DURATION_MINUTES
            )

        await self.db.commit()

    async def _reset_failed_attempts(self, user: User) -> None:
        """Reset failed login attempts."""
        if user.failed_login_attempts > 0:
            user.failed_login_attempts = 0
            user.locked_until = None
            await self.db.commit()

    async def _get_user_membership(self, user_id: int, organization_id: int) -> Membership | None:
        """Get user membership in organization."""
        result = await self.db.execute(
            select(Membership).where(
                Membership.user_id == user_id,
                Membership.organization_id == organization_id,
            )
        )
        return result.scalar_one_or_none()

    def _create_user_profile(self, user: User) -> UserProfile:
        """Create UserProfile from User model."""
        return UserProfile(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=user.full_name,
            is_verified=user.is_verified,
            is_superuser=user.is_superuser,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )

    def _create_api_key_response(self, api_key: APIKey) -> APIKeyResponse:
        """Create APIKeyResponse from APIKey model."""
        return APIKeyResponse(
            id=api_key.id,
            name=api_key.name,
            prefix=api_key.prefix,
            scopes=api_key.scopes_list,
            is_valid=api_key.is_valid,
            last_used_at=api_key.last_used_at,
            usage_count=api_key.usage_count,
            expires_at=api_key.expires_at,
            created_at=api_key.created_at,
        )

    async def create_login_response(
        self,
        user: User,
        tokens: dict[str, str] | None,
        device_info: dict[str, str],
        client_type: str,
    ) -> LoginResponse:
        """Create complete login response."""
        user_profile = self._create_user_profile(user)

        response_tokens = TokenResponse(**tokens) if tokens else None

        return LoginResponse(
            success=True,
            message=f"Login successful ({client_type} client)",
            user=user_profile,
            tokens=response_tokens,
            device_info=device_info,
        )

    async def get_api_keys_list(self, user_id: int) -> list[APIKeyResponse]:
        """Get list of API keys as response objects."""
        api_keys = await self.list_api_keys(user_id)
        return [self._create_api_key_response(key) for key in api_keys]

    async def logout_by_access_token(self, access_token: str, user_id: int) -> bool:
        """Logout by extracting session ID from access token."""
        try:
            payload = self.jwt_service.decode_access_token(access_token)
            session_id = payload.get("session_id")

            if session_id:
                await self.logout_session_by_id(session_id, user_id)
                return True
        except Exception:
            pass
        return False
