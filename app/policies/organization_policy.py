"""Organization-specific authorization policies."""

from app.models.membership import Role

from .base_policy import Action, BasePolicy, PolicyContext, PolicyResult


class OrganizationPolicy(BasePolicy):
    """Authorization policies for organization management."""

    def check(self, action: Action, context: PolicyContext) -> PolicyResult:
        """Check organization authorization."""

        # Always require authentication
        auth_check = self._require_authentication(context)
        if auth_check:
            return auth_check

        # Route to specific action handlers
        if action == Action.CREATE:
            return self._check_create(context)
        elif action == Action.READ:
            return self._check_read(context)
        elif action == Action.UPDATE:
            return self._check_update(context)
        elif action == Action.DELETE:
            return self._check_delete(context)
        elif action == Action.MANAGE:
            return self._check_manage(context)
        else:
            return PolicyResult.deny(
                f"Action {action.value} not supported for organization resource"
            )

    def _check_create(self, context: PolicyContext) -> PolicyResult:
        """Check create permissions for organizations."""
        # Any authenticated user can create an organization
        # This is the key difference from other resources
        return PolicyResult.allow("Authenticated users can create organizations")

    def _check_read(self, context: PolicyContext) -> PolicyResult:
        """Check read permissions for organizations."""
        # Reading organization requires being a member of that organization
        if not context.is_organization_member():
            return PolicyResult.deny("Must be organization member to read organization details")

        return PolicyResult.allow()

    def _check_update(self, context: PolicyContext) -> PolicyResult:
        """Check update permissions for organizations."""
        # Only OWNER and ADMIN can update organization
        if not context.is_organization_member():
            return PolicyResult.deny("Must be organization member to update organization")

        user_role = context.get_role()
        if user_role not in [Role.OWNER, Role.ADMIN]:
            return PolicyResult.deny("Must be OWNER or ADMIN to update organization")

        return PolicyResult.allow()

    def _check_delete(self, context: PolicyContext) -> PolicyResult:
        """Check delete permissions for organizations."""
        # Only OWNER can delete organization
        if not context.is_organization_member():
            return PolicyResult.deny("Must be organization member to delete organization")

        user_role = context.get_role()
        if user_role != Role.OWNER:
            return PolicyResult.deny("Must be OWNER to delete organization")

        return PolicyResult.allow()

    def _check_manage(self, context: PolicyContext) -> PolicyResult:
        """Check manage permissions for organizations (e.g., adding/removing members)."""
        # Only OWNER and ADMIN can manage organization members
        if not context.is_organization_member():
            return PolicyResult.deny("Must be organization member to manage organization")

        user_role = context.get_role()
        if user_role not in [Role.OWNER, Role.ADMIN]:
            return PolicyResult.deny("Must be OWNER or ADMIN to manage organization")

        return PolicyResult.allow()
