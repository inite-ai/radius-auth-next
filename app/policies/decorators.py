"""Authorization decorators for FastAPI routes."""

from functools import wraps
from typing import Any, Callable, Optional

from fastapi import Depends, HTTPException, Request, status

from app.dependencies.auth import get_current_active_user
from app.models.membership import Role
from app.models.user import User

from .base_policy import Action
from .guards import can, require_role as _require_role


def authorize(
    action: Action,
    resource_type: str = "resource",
    organization_id_param: str = "organization_id",
    resource_id_param: Optional[str] = None,
    resource_param: Optional[str] = None,
):
    """
    Decorator to authorize FastAPI route access.
    
    Usage:
        @authorize(Action.UPDATE, "user", resource_id_param="user_id")
        async def update_user(user_id: int, current_user: User = Depends(get_current_active_user)):
            pass
        
        @authorize(Action.CREATE, "document", organization_id_param="org_id")
        async def create_document(org_id: int, current_user: User = Depends(get_current_active_user)):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current user from dependencies
            current_user = kwargs.get("current_user")
            if not current_user:
                # Try to get from args if it's a method
                for arg in args:
                    if isinstance(arg, User):
                        current_user = arg
                        break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )
            
            # Extract parameters
            organization_id = kwargs.get(organization_id_param)
            resource_id = kwargs.get(resource_id_param) if resource_id_param else None
            resource = kwargs.get(resource_param) if resource_param else None
            
            # Check authorization
            if not can(
                user=current_user,
                action=action,
                resource_type=resource_type,
                resource=resource,
                resource_id=resource_id,
                organization_id=organization_id,
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied",
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_permission(
    action: Action,
    resource_type: str = "resource",
):
    """
    Simplified permission decorator that extracts context from request.
    
    Usage:
        @require_permission(Action.UPDATE, "user")
        async def update_user(
            user_id: int,
            request: Request,
            current_user: User = Depends(get_current_active_user)
        ):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            current_user: User = kwargs.get("current_user")
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )
            
            # Extract organization_id from path parameters
            organization_id = request.path_params.get("organization_id")
            if not organization_id:
                # Try to get from query parameters
                organization_id = request.query_params.get("organization_id")
            
            # Extract resource_id from path parameters
            resource_id = None
            for param_name, param_value in request.path_params.items():
                if param_name.endswith("_id") and param_name != "organization_id":
                    resource_id = param_value
                    break
            
            # Check authorization
            if not can(
                user=current_user,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                organization_id=organization_id,
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied",
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_role(
    role: Role,
    organization_id_param: str = "organization_id",
):
    """
    Decorator to require specific role in organization.
    
    Usage:
        @require_role(Role.ADMIN, organization_id_param="org_id")
        async def admin_function(org_id: int, current_user: User = Depends(get_current_active_user)):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user: User = kwargs.get("current_user")
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )
            
            organization_id = kwargs.get(organization_id_param)
            if not organization_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Organization ID required",
                )
            
            _require_role(current_user, role, organization_id)
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_superuser(func: Callable) -> Callable:
    """
    Decorator to require superuser access.
    
    Usage:
        @require_superuser
        async def admin_function(current_user: User = Depends(get_current_active_user)):
            pass
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        current_user: User = kwargs.get("current_user")
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        
        if not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser access required",
            )
        
        return await func(*args, **kwargs)
    
    return wrapper
