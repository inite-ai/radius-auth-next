"""Base router class with common functionality."""

import logging
from typing import Any

from fastapi import APIRouter, Depends

from app.constants import APIStatus
from app.dependencies.auth import get_current_active_user, get_current_organization
from app.dependencies.database import get_db
from app.models.organization import Organization
from app.models.user import User
from app.utils.response_builders import ResponseBuilder

logger = logging.getLogger(__name__)


class BaseRouter:
    """Base router class with common dependencies and utilities."""

    def __init__(
        self,
        prefix: str = "",
        tags: list[str] | None = None,
        dependencies: list[Any] | None = None,
    ):
        """
        Initialize base router.

        Args:
            prefix: URL prefix for all routes
            tags: OpenAPI tags
            dependencies: Common dependencies for all routes
        """
        self.router = APIRouter(prefix=prefix, tags=tags or [], dependencies=dependencies or [])
        self.response_builder = ResponseBuilder()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def get_common_dependencies(self) -> dict[str, Any]:
        """Get common dependency mappings."""
        return {
            "current_user": Depends(get_current_active_user),
            "organization": Depends(get_current_organization),
            "db": Depends(get_db),
        }

    def log_operation(self, operation: str, resource_type: str, user_id: int, **context):
        """Log router operations for auditing."""
        self.logger.info(
            f"User {user_id} performed {operation} on {resource_type}",
            extra={
                "operation": operation,
                "resource_type": resource_type,
                "user_id": user_id,
                **context,
            },
        )

    def success_response(self, message: str = "Operation successful", **data):
        """Create standardized success response."""
        return self.response_builder.success(message, **data)

    def created_response(self, resource_type: str, resource_data: Any):
        """Create standardized creation response."""
        return self.response_builder.success(
            f"{resource_type.title()} created successfully", data=resource_data
        )

    def updated_response(self, resource_type: str, resource_data: Any):
        """Create standardized update response."""
        return self.response_builder.success(
            f"{resource_type.title()} updated successfully", data=resource_data
        )

    def deleted_response(self, resource_type: str):
        """Create standardized deletion response."""
        return self.response_builder.resource_deleted(resource_type)


class CRUDRouter(BaseRouter):
    """Router with CRUD operation helpers."""

    def __init__(
        self,
        prefix: str = "",
        tags: list[str] | None = None,
        dependencies: list[Any] | None = None,
        resource_name: str = "resource",
    ):
        super().__init__(prefix, tags, dependencies)
        self.resource_name = resource_name

    def add_crud_routes(
        self,
        service_class: type,
        create_schema: type,
        update_schema: type,
        response_schema: type,
        list_response_schema: type,
    ):
        """
        Add standard CRUD routes.

        This is a template method - subclasses should implement actual routes.
        """
        pass

    def get_success_status(self, method: str) -> int:
        """Get appropriate status code for HTTP method."""
        status_map = {
            "GET": APIStatus.SUCCESS,
            "POST": APIStatus.CREATED,
            "PUT": APIStatus.SUCCESS,
            "PATCH": APIStatus.SUCCESS,
            "DELETE": APIStatus.NO_CONTENT,
        }
        return status_map.get(method.upper(), APIStatus.SUCCESS)


class AuthenticatedRouter(BaseRouter):
    """Router that requires authentication for all routes."""

    def __init__(
        self,
        prefix: str = "",
        tags: list[str] | None = None,
        dependencies: list[Any] | None = None,
    ):
        # Add authentication dependency to all routes
        auth_deps = dependencies or []
        auth_deps.append(Depends(get_current_active_user))
        super().__init__(prefix, tags, auth_deps)

    def require_user(self, user: User) -> User:
        """Validate user is authenticated and active."""
        if not user or not user.is_active:
            self.logger.warning(f"Inactive user attempted access: {user.id if user else 'None'}")
            raise ValueError("User is not active")
        return user

    def require_organization_access(self, user: User, organization: Organization | None) -> bool:
        """Check if user has access to organization."""
        if not organization:
            return True  # No organization context required

        # Implementation would check user's membership in organization
        # For now, just return True
        return True


class ResourceRouter(CRUDRouter):
    """Router for resource management with permissions."""

    def __init__(
        self,
        prefix: str = "",
        tags: list[str] | None = None,
        dependencies: list[Any] | None = None,
        resource_name: str = "resource",
        require_organization: bool = False,
    ):
        super().__init__(prefix, tags, dependencies, resource_name)
        self.require_organization = require_organization

    def check_resource_permissions(
        self,
        user: User,
        action: str,
        resource_id: int | None = None,
        organization: Organization | None = None,
    ):
        """Check if user has permission for resource action."""
        from app.policies.base_policy import Action
        from app.policies.guards import require

        # Map string actions to enum
        action_map = {
            "create": Action.CREATE,
            "read": Action.READ,
            "update": Action.UPDATE,
            "delete": Action.DELETE,
        }

        require(
            user=user,
            action=action_map.get(action, Action.READ),
            resource_type=self.resource_name,
            resource_id=resource_id,
            organization_id=organization.id if organization else None,
        )

    def log_resource_operation(
        self,
        operation: str,
        user: User,
        resource_id: int | None = None,
        organization: Organization | None = None,
        **context,
    ):
        """Log resource operation with context."""
        self.log_operation(
            operation,
            self.resource_name,
            user.id,
            resource_id=resource_id,
            organization_id=organization.id if organization else None,
            **context,
        )


# Factory functions for common router types
def create_user_router() -> ResourceRouter:
    """Create router for user management."""
    return ResourceRouter(
        prefix="/users",
        tags=["users"],
        resource_name="user",
        require_organization=False,
    )


def create_organization_router() -> ResourceRouter:
    """Create router for organization management."""
    return ResourceRouter(
        prefix="/organizations",
        tags=["organizations"],
        resource_name="organization",
        require_organization=True,
    )


def create_auth_router() -> BaseRouter:
    """Create router for authentication."""
    return BaseRouter(prefix="/auth", tags=["authentication"])


def create_oauth_router() -> AuthenticatedRouter:
    """Create router for OAuth operations."""
    return AuthenticatedRouter(prefix="/oauth", tags=["oauth"])


def create_session_router() -> AuthenticatedRouter:
    """Create router for session management."""
    return AuthenticatedRouter(prefix="/sessions", tags=["sessions"])
