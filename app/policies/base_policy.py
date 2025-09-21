"""Base policy classes and types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from app.models.membership import Role
from app.models.user import User


class Action(str, Enum):
    """Standard actions for authorization."""
    
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    
    # Admin actions
    MANAGE = "manage"
    ADMIN = "admin"
    
    # User-specific actions
    INVITE = "invite"
    REMOVE = "remove"
    
    # Content actions
    PUBLISH = "publish"
    MODERATE = "moderate"


@dataclass
class PolicyContext:
    """Context for policy evaluation."""
    
    user: User
    organization_id: Optional[int] = None
    resource: Optional[Any] = None
    resource_id: Optional[int] = None
    extra_data: Optional[Dict[str, Any]] = None
    
    def get_membership(self) -> Optional["Membership"]:
        """Get user's membership in the current organization."""
        if not self.organization_id:
            return None
        
        for membership in self.user.memberships:
            if (membership.organization_id == self.organization_id 
                and membership.is_active):
                return membership
        return None
    
    def get_role(self) -> Optional[Role]:
        """Get user's role in the current organization."""
        membership = self.get_membership()
        return membership.role if membership else None
    
    def is_organization_member(self) -> bool:
        """Check if user is a member of the organization."""
        return self.get_membership() is not None
    
    def has_role(self, role: Role) -> bool:
        """Check if user has a specific role."""
        user_role = self.get_role()
        return user_role == role if user_role else False
    
    def has_role_or_higher(self, role: Role) -> bool:
        """Check if user has a role or higher."""
        user_role = self.get_role()
        if not user_role:
            return False
        
        # Role hierarchy: owner > admin > editor > viewer
        role_hierarchy = {
            Role.VIEWER: 1,
            Role.EDITOR: 2,
            Role.ADMIN: 3,
            Role.OWNER: 4,
        }
        
        user_level = role_hierarchy.get(user_role, 0)
        required_level = role_hierarchy.get(role, 0)
        
        return user_level >= required_level


@dataclass
class PolicyResult:
    """Result of policy evaluation."""
    
    allowed: bool
    reason: Optional[str] = None
    
    @classmethod
    def allow(cls, reason: Optional[str] = None) -> "PolicyResult":
        """Create an allow result."""
        return cls(allowed=True, reason=reason)
    
    @classmethod
    def deny(cls, reason: str) -> "PolicyResult":
        """Create a deny result."""
        return cls(allowed=False, reason=reason)


class BasePolicy(ABC):
    """Base class for all authorization policies."""
    
    @abstractmethod
    def check(self, action: Action, context: PolicyContext) -> PolicyResult:
        """Check if action is allowed in the given context."""
        pass
    
    def _require_authentication(self, context: PolicyContext) -> Optional[PolicyResult]:
        """Check if user is authenticated."""
        if not context.user:
            return PolicyResult.deny("Authentication required")
        
        if not context.user.is_active:
            return PolicyResult.deny("User account is inactive")
        
        if not context.user.can_login:
            return PolicyResult.deny("User account is locked or unverified")
        
        return None
    
    def _require_organization_membership(self, context: PolicyContext) -> Optional[PolicyResult]:
        """Check if user is a member of the organization."""
        if not context.organization_id:
            return PolicyResult.deny("Organization context required")
        
        if not context.is_organization_member():
            return PolicyResult.deny("Organization membership required")
        
        return None
    
    def _require_role(self, context: PolicyContext, required_role: Role) -> Optional[PolicyResult]:
        """Check if user has the required role or higher."""
        if not context.has_role_or_higher(required_role):
            return PolicyResult.deny(f"Role '{required_role}' or higher required")
        
        return None
    
    def _is_resource_owner(self, context: PolicyContext) -> bool:
        """Check if user owns the resource."""
        if not context.resource:
            return False
        
        # Check if resource has user_id attribute
        if hasattr(context.resource, "user_id"):
            return context.resource.user_id == context.user.id
        
        # Check if resource has created_by attribute
        if hasattr(context.resource, "created_by"):
            return context.resource.created_by == context.user.id
        
        return False
    
    def _is_same_user(self, context: PolicyContext) -> bool:
        """Check if the resource is the user themselves."""
        if not context.resource_id:
            return False
        
        return context.resource_id == context.user.id
