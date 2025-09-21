"""Response builder utilities for consistent API responses."""

from typing import Any

from app.models.organization import Organization
from app.models.user import User
from app.schemas.auth import APIKeyCreateResponse, APIKeyListResponse, LoginResponse
from app.schemas.common import BaseResponse
from app.schemas.organization import OrganizationDetailResponse, OrganizationListResponse
from app.schemas.user import UserDetailResponse, UserListResponse, UserResponse


class ResponseBuilder:
    """Builder class for standardized API responses."""

    @staticmethod
    def success(message: str = "Operation successful", **data) -> BaseResponse:
        """Build a simple success response."""
        return BaseResponse(success=True, message=message, **data)

    @staticmethod
    def user_detail(user: User, message: str = "User retrieved successfully") -> UserDetailResponse:
        """Build user detail response."""
        return UserDetailResponse(
            success=True,
            message=message,
            user=UserResponse.model_validate(user),
        )

    @staticmethod
    def user_created(user: User) -> UserDetailResponse:
        """Build user creation response."""
        return ResponseBuilder.user_detail(user, "User created successfully")

    @staticmethod
    def user_updated(user: User) -> UserDetailResponse:
        """Build user update response."""
        return ResponseBuilder.user_detail(user, "User updated successfully")

    @staticmethod
    def user_list(
        users: list[User],
        total: int,
        page: int = 1,
        per_page: int = 20,
        message: str = "Users retrieved successfully",
    ) -> UserListResponse:
        """Build user list response."""
        return UserListResponse(
            success=True,
            message=message,
            users=[UserResponse.model_validate(user) for user in users],
            total=total,
            page=page,
            per_page=per_page,
        )

    @staticmethod
    def organization_detail(
        organization: Organization,
        user_role: str | None = None,
        message: str = "Organization retrieved successfully",
    ) -> OrganizationDetailResponse:
        """Build organization detail response."""
        from app.schemas.organization import OrganizationResponse

        return OrganizationDetailResponse(
            success=True,
            message=message,
            organization=OrganizationResponse.model_validate(organization),
            user_role=user_role,
        )

    @staticmethod
    def organization_created(
        organization: Organization, user_role: str = "owner"
    ) -> OrganizationDetailResponse:
        """Build organization creation response."""
        return ResponseBuilder.organization_detail(
            organization, user_role, "Organization created successfully"
        )

    @staticmethod
    def organization_updated(
        organization: Organization, user_role: str | None = None
    ) -> OrganizationDetailResponse:
        """Build organization update response."""
        return ResponseBuilder.organization_detail(
            organization, user_role, "Organization updated successfully"
        )

    @staticmethod
    def organization_list(
        organizations: list[Any], total: int, message: str = "Organizations retrieved successfully"
    ) -> OrganizationListResponse:
        """Build organization list response."""
        from app.schemas.organization import OrganizationWithRole

        return OrganizationListResponse(
            success=True,
            message=message,
            organizations=[OrganizationWithRole.model_validate(org) for org in organizations],
            total=total,
        )

    @staticmethod
    def login_success(access_token: str, refresh_token: str, user: User) -> LoginResponse:
        """Build login success response."""
        return LoginResponse(
            success=True,
            message="Login successful",
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            user=UserResponse.model_validate(user),
        )

    @staticmethod
    def logout_success() -> BaseResponse:
        """Build logout success response."""
        return ResponseBuilder.success("Logout successful")

    @staticmethod
    def password_changed() -> BaseResponse:
        """Build password change success response."""
        return ResponseBuilder.success("Password changed successfully. Please log in again.")

    @staticmethod
    def api_key_created(api_key: str, key_data: Any) -> APIKeyCreateResponse:
        """Build API key creation response."""
        from app.schemas.auth import APIKeyResponse

        return APIKeyCreateResponse(
            success=True,
            message="API key created successfully",
            api_key=api_key,
            key_info=APIKeyResponse.model_validate(key_data),
        )

    @staticmethod
    def api_key_list(api_keys: list[Any]) -> APIKeyListResponse:
        """Build API key list response."""
        from app.schemas.auth import APIKeyResponse

        return APIKeyListResponse(
            success=True,
            message="API keys retrieved successfully",
            api_keys=[APIKeyResponse.model_validate(key) for key in api_keys],
        )

    @staticmethod
    def resource_deleted(resource_type: str) -> BaseResponse:
        """Build resource deletion response."""
        return ResponseBuilder.success(f"{resource_type.title()} deleted successfully")

    @staticmethod
    def resource_deactivated(resource_type: str) -> BaseResponse:
        """Build resource deactivation response."""
        return ResponseBuilder.success(f"{resource_type.title()} deactivated successfully")

    @staticmethod
    def sessions_revoked(count: int) -> BaseResponse:
        """Build sessions revoked response."""
        return ResponseBuilder.success(f"Revoked {count} sessions", revoked_sessions=count)

    @staticmethod
    def session_revoked() -> BaseResponse:
        """Build single session revoked response."""
        return ResponseBuilder.success("Session revoked successfully")


# Convenience functions for common patterns
def success_response(message: str = "Operation successful", **data) -> BaseResponse:
    """Quick success response."""
    return ResponseBuilder.success(message, **data)


def user_response(user: User, message: str = "User retrieved successfully") -> UserDetailResponse:
    """Quick user response."""
    return ResponseBuilder.user_detail(user, message)


def organization_response(
    organization: Organization,
    user_role: str | None = None,
    message: str = "Organization retrieved successfully",
) -> OrganizationDetailResponse:
    """Quick organization response."""
    return ResponseBuilder.organization_detail(organization, user_role, message)
