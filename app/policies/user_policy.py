"""User-related authorization policies."""

from app.models.membership import Role

from .base_policy import Action, BasePolicy, PolicyContext, PolicyResult


class UserPolicy(BasePolicy):
    """Authorization policies for user operations."""

    def check(self, action: Action, context: PolicyContext) -> PolicyResult:
        """Check user authorization."""

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
        """Check read access to users."""

        # Superusers can read all users
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Users can always read their own profile
        if self._is_same_user(context):
            return PolicyResult.allow("Self access")

        # Organization context required for reading other users
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Organization members can read other members
        return PolicyResult.allow("Organization member access")

    def _check_create(self, context: PolicyContext) -> PolicyResult:
        """Check user creation access."""

        # Superusers can create users anywhere
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # If no organization context, only superusers can create users
        if not context.organization_id:
            if context.user.is_superuser:
                return PolicyResult.allow("Superuser can create users")
            return PolicyResult.deny("Organization context required for user creation")

        # Organization context required for organization-specific user creation
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # NOTE: Organization user limit check temporarily disabled due to async database access issues
        # TODO: Implement proper async user limit checking when needed
        # membership = context.get_membership()
        # if membership and not membership.organization.can_add_users:
        #     return PolicyResult.deny("Organization user limit reached")

        # Admins and owners can create users
        role_check = self._require_role(context, Role.ADMIN)
        if role_check:
            return role_check

        return PolicyResult.allow("Admin/Owner access")

    def _check_update(self, context: PolicyContext) -> PolicyResult:
        """Check user update access."""

        # Superusers can update all users
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Users can always update their own profile
        if self._is_same_user(context):
            return PolicyResult.allow("Self update")

        # Organization context required for updating other users
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Admins and owners can update users
        role_check = self._require_role(context, Role.ADMIN)
        if role_check:
            return role_check

        return PolicyResult.allow("Admin/Owner access")

    def _check_delete(self, context: PolicyContext) -> PolicyResult:
        """Check user deletion access."""

        # Superusers can delete users
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Users cannot delete themselves
        if self._is_same_user(context):
            return PolicyResult.deny("Cannot delete self")

        # Organization context required
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Admins and owners can delete users
        role_check = self._require_role(context, Role.ADMIN)
        if role_check:
            return role_check

        return PolicyResult.allow("Admin/Owner access")

    def _check_manage(self, context: PolicyContext) -> PolicyResult:
        """Check user management access."""

        # Superusers can manage all users
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Organization context required
        org_check = self._require_organization_membership(context)
        if org_check:
            return org_check

        # Admins and owners can manage users
        role_check = self._require_role(context, Role.ADMIN)
        if role_check:
            return role_check

        return PolicyResult.allow("Admin/Owner access")
