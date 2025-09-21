"""Permission decorators for route protection."""

import functools
from collections.abc import Callable

from app.models.organization import Organization
from app.models.user import User
from app.policies.base_policy import Action
from app.policies.guards import require


def require_permission(
    action: Action,
    resource_type: str,
    resource_id_param: str | None = None,
    organization_dependent: bool = True,
):
    """
    Decorator for requiring specific permissions on routes.

    Args:
        action: The action to check (READ, CREATE, UPDATE, DELETE)
        resource_type: Type of resource being accessed
        resource_id_param: Name of parameter that contains resource ID (optional)
        organization_dependent: Whether this check is organization-dependent

    Usage:
        @require_permission(Action.READ, "user", "user_id")
        async def get_user(user_id: int, current_user: User = Depends(get_current_active_user)):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract dependencies from kwargs
            current_user = None
            organization = None
            resource_id = None

            # Find current_user in kwargs
            for _key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break

            # Find organization if organization_dependent
            if organization_dependent:
                for _key, value in kwargs.items():
                    if isinstance(value, Organization):
                        organization = value
                        break

            # Find resource_id if specified
            if resource_id_param and resource_id_param in kwargs:
                resource_id = kwargs[resource_id_param]

            # Perform permission check
            require(
                user=current_user,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                organization_id=organization.id if organization else None,
            )

            # Call the original function
            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_user_permission(action: Action, resource_id_param: str = "user_id"):
    """Shortcut decorator for user resource permissions."""
    return require_permission(action, "user", resource_id_param)


def require_organization_permission(action: Action, resource_id_param: str = "organization_id"):
    """Shortcut decorator for organization resource permissions."""
    return require_permission(action, "organization", resource_id_param)


def require_create_permission(resource_type: str):
    """Shortcut decorator for create permissions."""
    return require_permission(Action.CREATE, resource_type, None)


def require_read_permission(resource_type: str, resource_id_param: str | None = None):
    """Shortcut decorator for read permissions."""
    return require_permission(Action.READ, resource_type, resource_id_param)


def require_update_permission(resource_type: str, resource_id_param: str | None = None):
    """Shortcut decorator for update permissions."""
    return require_permission(Action.UPDATE, resource_type, resource_id_param)


def require_delete_permission(resource_type: str, resource_id_param: str | None = None):
    """Shortcut decorator for delete permissions."""
    return require_permission(Action.DELETE, resource_type, resource_id_param)


# Validation decorators
def validate_user_exists(user_id_param: str = "user_id"):
    """Decorator to validate that user exists before route execution."""
    import functools

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            from sqlalchemy.ext.asyncio import AsyncSession

            from app.services.user_service import UserService

            # Find database session
            db = None
            for value in kwargs.values():
                if isinstance(value, AsyncSession):
                    db = value
                    break

            if not db:
                raise ValueError("No database session found in function arguments")

            # Get user_id from kwargs
            user_id = kwargs.get(user_id_param)
            if not user_id:
                raise ValueError(f"Parameter '{user_id_param}' not found")

            # Validate user exists
            user_service = UserService(db)
            await user_service.get_user_by_id(user_id)  # Will raise NotFoundError if not exists

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_organization_exists(org_id_param: str = "organization_id"):
    """Decorator to validate that organization exists before route execution."""
    import functools

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            from sqlalchemy.ext.asyncio import AsyncSession

            from app.services.organization_service import OrganizationService

            # Find database session
            db = None
            for value in kwargs.values():
                if isinstance(value, AsyncSession):
                    db = value
                    break

            if not db:
                raise ValueError("No database session found in function arguments")

            # Get organization_id from kwargs
            org_id = kwargs.get(org_id_param)
            if not org_id:
                raise ValueError(f"Parameter '{org_id_param}' not found")

            # Validate organization exists
            org_service = OrganizationService(db)
            organization = await org_service.get_organization_by_id(org_id)
            if not organization:
                from app.utils.exceptions import NotFoundError

                raise NotFoundError("Organization not found")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_organization_membership(org_id_param: str = "organization_id"):
    """Decorator to validate that current user is member of organization."""
    import functools

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            from sqlalchemy.ext.asyncio import AsyncSession

            from app.models.user import User
            from app.services.organization_service import OrganizationService

            # Find dependencies in kwargs
            current_user = None
            db = None

            for _key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                elif isinstance(value, AsyncSession):
                    db = value

            if not current_user or not db:
                raise ValueError("Current user and database session required")

            # Get organization_id from kwargs
            org_id = kwargs.get(org_id_param)
            if not org_id:
                raise ValueError(f"Parameter '{org_id_param}' not found")

            # Check membership
            org_service = OrganizationService(db)
            role = await org_service.get_user_role_in_organization(current_user.id, org_id)
            if not role:
                from app.utils.exceptions import AuthorizationError

                raise AuthorizationError("User is not a member of this organization")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def validate_resource_ownership(
    resource_type: str, resource_id_param: str, owner_field: str = "user_id"
):
    """Decorator to validate that current user owns the resource."""
    import functools

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            from sqlalchemy import select
            from sqlalchemy.ext.asyncio import AsyncSession

            from app.models.user import User

            # Find dependencies
            current_user = None
            db = None

            for _key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                elif isinstance(value, AsyncSession):
                    db = value

            if not current_user or not db:
                raise ValueError("Current user and database session required")

            # Get resource_id from kwargs
            resource_id = kwargs.get(resource_id_param)
            if not resource_id:
                raise ValueError(f"Parameter '{resource_id_param}' not found")

            # Import the model dynamically
            if resource_type == "user":
                from app.models.user import User as ResourceModel
            elif resource_type == "organization":
                from app.models.organization import Organization as ResourceModel
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")

            # Check ownership
            result = await db.execute(select(ResourceModel).where(ResourceModel.id == resource_id))
            resource = result.scalar_one_or_none()

            if not resource:
                from app.utils.exceptions import NotFoundError

                raise NotFoundError(f"{resource_type.title()} not found")

            if getattr(resource, owner_field, None) != current_user.id:
                from app.utils.exceptions import AuthorizationError

                raise AuthorizationError(f"You don't own this {resource_type}")

            return await func(*args, **kwargs)

        return wrapper

    return decorator
