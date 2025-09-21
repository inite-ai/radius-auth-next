"""Session-specific authorization policies."""


from .base_policy import Action, BasePolicy, PolicyContext, PolicyResult


class SessionPolicy(BasePolicy):
    """Authorization policies for session management - user-level, no organization context required."""

    def check(self, action: Action, context: PolicyContext) -> PolicyResult:
        """Check session authorization."""

        # Always require authentication
        auth_check = self._require_authentication(context)
        if auth_check:
            return auth_check

        # Route to specific action handlers
        if action == Action.READ:
            return self._check_read(context)
        elif action == Action.DELETE:
            return self._check_delete(context)
        else:
            return PolicyResult.deny(f"Action {action} not allowed on sessions")

    def _check_read(self, context: PolicyContext) -> PolicyResult:
        """Check read access to user's sessions."""

        # Superusers can read all sessions
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Users can read their own sessions
        return PolicyResult.allow("User can read own sessions")

    def _check_delete(self, context: PolicyContext) -> PolicyResult:
        """Check delete access to user's sessions."""

        # Superusers can delete any sessions
        if context.user.is_superuser:
            return PolicyResult.allow("Superuser access")

        # Users can delete their own sessions
        return PolicyResult.allow("User can delete own sessions")
