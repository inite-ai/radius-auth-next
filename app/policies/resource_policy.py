"""Generic resource authorization policies."""

from app.models.membership import Role

from .base_policy import Action, BasePolicy, PolicyContext, PolicyResult


class ResourcePolicy(BasePolicy):
    """Generic authorization policies for resources within organizations."""

    def check(self, action: Action, context: PolicyContext) -> PolicyResult:
        """Check resource authorization."""

        # Always require authentication
        auth_check = self._require_authentication(context)
        if auth_check:
            return auth_check

        # Route to specific action handlers
        if action == Action.READ:
            return self._check_read(context)
        elif action == Action.CREATE:
            return self._check_create(context)
        elif action == Action.UPDATE:
            return self._check_update(context)
        elif action == Action.DELETE:
            return self._check_delete(context)
        elif action == Action.MANAGE:
            return self._check_manage(context)
        else:
            return PolicyResult.deny(f"Unknown action: {action}")

    def _check_read(self, context: PolicyContext) -> PolicyResult:
        """Check read access to resources."""

        # Superusers can read all resources
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Check if resource belongs to organization
        if not self._resource_belongs_to_organization(context):
            return PolicyResult.deny("Resource does not belong to user's organization")

        # Organization members can read resources
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        return PolicyResult.allow("Organization member access")

    def _check_create(self, context: PolicyContext) -> PolicyResult:
        """Check resource creation access."""

        # Superusers can create resources
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Organization context required
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Editors and above can create resources
        role_check = self._require_role(context, Role.EDITOR)
        if role_check:
            return role_check

        return PolicyResult.allow("Editor+ access")

    def _check_update(self, context: PolicyContext) -> PolicyResult:
        """Check resource update access."""

        # Superusers can update all resources
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Check if resource belongs to organization
        if not self._resource_belongs_to_organization(context):
            return PolicyResult.deny("Resource does not belong to user's organization")

        # Organization context required
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Resource owners can update their own resources
        if self._is_resource_owner(context):
            return PolicyResult.allow("Resource owner access")

        # Editors and above can update resources
        role_check = self._require_role(context, Role.EDITOR)
        if role_check:
            return role_check

        return PolicyResult.allow("Editor+ access")

    def _check_delete(self, context: PolicyContext) -> PolicyResult:
        """Check resource deletion access."""

        # Superusers can delete all resources
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Check if resource belongs to organization
        if not self._resource_belongs_to_organization(context):
            return PolicyResult.deny("Resource does not belong to user's organization")

        # Organization context required
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Resource owners can delete their own resources
        if self._is_resource_owner(context):
            return PolicyResult.allow("Resource owner access")

        # Admins and above can delete resources
        role_check = self._require_role(context, Role.ADMIN)
        if role_check:
            return role_check

        return PolicyResult.allow("Admin+ access")

    def _check_manage(self, context: PolicyContext) -> PolicyResult:
        """Check resource management access."""

        # Superusers can manage all resources
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Organization context required
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Admins and above can manage resources
        role_check = self._require_role(context, Role.ADMIN)
        if role_check:
            return role_check

        return PolicyResult.allow("Admin+ access")

    def _resource_belongs_to_organization(self, context: PolicyContext) -> bool:
        """Check if resource belongs to the user's organization."""
        if not context.resource or not context.organization_id:
            return True  # No resource to check or no org context

        # Check if resource has organization_id attribute
        if hasattr(context.resource, "organization_id"):
            return context.resource.organization_id == context.organization_id

        # Check if resource has org_id attribute
        if hasattr(context.resource, "org_id"):
            return context.resource.org_id == context.organization_id

        # If no organization field, assume it belongs
        return True
