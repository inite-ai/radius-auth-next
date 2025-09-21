"""Guard helpers for authorization checks."""

from typing import Any

from fastapi import HTTPException, status

from app.models.membership import Role
from app.models.user import User

from .base_policy import Action, BasePolicy, PolicyContext
from .resource_policy import ResourcePolicy
from .user_policy import UserPolicy

# Policy registry
POLICY_REGISTRY = {
    "user": UserPolicy,
    "resource": ResourcePolicy,
}


def can(
    user: User,
    action: Action,
    resource_type: str = "resource",
    resource: Any | None = None,
    resource_id: int | None = None,
    organization_id: int | None = None,
    **kwargs,
) -> bool:
    """
    Check if user can perform action on resource.

    Usage:
        can(user, Action.UPDATE, "user", user_id=123, organization_id=456)
        can(user, Action.CREATE, "document", organization_id=456)
        can(user, Action.DELETE, "document", resource=document)
    """
    context = PolicyContext(
        user=user,
        organization_id=organization_id,
        resource=resource,
        resource_id=resource_id,
        extra_data=kwargs,
    )

    policy_class = POLICY_REGISTRY.get(resource_type, ResourcePolicy)
    policy = policy_class()
    result = policy.check(action, context)

    return result.allowed


def require(
    user: User,
    action: Action,
    resource_type: str = "resource",
    resource: Any | None = None,
    resource_id: int | None = None,
    organization_id: int | None = None,
    **kwargs,
) -> None:
    """
    Require that user can perform action on resource.
    Raises HTTPException if not allowed.

    Usage:
        require(user, Action.UPDATE, "user", user_id=123, organization_id=456)
        require(user, Action.CREATE, "document", organization_id=456)
    """
    context = PolicyContext(
        user=user,
        organization_id=organization_id,
        resource=resource,
        resource_id=resource_id,
        extra_data=kwargs,
    )

    policy_class = POLICY_REGISTRY.get(resource_type, ResourcePolicy)
    policy = policy_class()
    result = policy.check(action, context)

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=result.reason or "Access denied",
        )


def require_role(
    user: User,
    required_role: Role,
    organization_id: int,
) -> None:
    """
    Require that user has specific role in organization.

    Usage:
        require_role(user, Role.ADMIN, organization_id=456)
    """
    context = PolicyContext(
        user=user,
        organization_id=organization_id,
    )

    if not context.has_role_or_higher(required_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{required_role}' or higher required",
        )


def require_organization_member(
    user: User,
    organization_id: int,
) -> None:
    """
    Require that user is a member of organization.

    Usage:
        require_organization_member(user, organization_id=456)
    """
    context = PolicyContext(
        user=user,
        organization_id=organization_id,
    )

    if not context.is_organization_member():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization membership required",
        )


def require_superuser(user: User) -> None:
    """
    Require that user is a superuser.

    Usage:
        require_superuser(user)
    """
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )


def require_active_user(user: User) -> None:
    """
    Require that user is active and can login.

    Usage:
        require_active_user(user)
    """
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    if not user.can_login:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is locked or unverified",
        )


def register_policy(resource_type: str, policy_class: type[BasePolicy]) -> None:
    """
    Register a custom policy for a resource type.

    Usage:
        register_policy("document", DocumentPolicy)
    """
    POLICY_REGISTRY[resource_type] = policy_class
