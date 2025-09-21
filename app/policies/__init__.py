"""Authorization policies system."""

from .base_policy import BasePolicy, PolicyContext, PolicyResult
from .decorators import authorize, require_permission, require_role
from .guards import can, require
from .resource_policy import ResourcePolicy
from .user_policy import UserPolicy

__all__ = [
    "BasePolicy",
    "PolicyContext", 
    "PolicyResult",
    "UserPolicy",
    "ResourcePolicy",
    "authorize",
    "require_permission",
    "require_role",
    "can",
    "require",
]
