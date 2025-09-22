"""Client detection and device info service."""

from fastapi import Request, Response

from app.config.settings import settings
from app.utils.device_detection import detect_client_type, get_device_info, should_use_cookies


class ClientService:
    """Service for handling client-specific operations."""

    @staticmethod
    def detect_client_info(request: Request) -> tuple[str, str, str]:
        """Detect client type, device name and device type from request."""
        user_agent = request.headers.get("User-Agent")
        client_type = detect_client_type(user_agent, request.headers.get("Accept"))
        device_name, device_type = get_device_info(user_agent)

        return client_type, device_name, device_type

    @staticmethod
    def set_session_cookies(
        response: Response,
        refresh_token: str,
        client_type: str,
        remember_me: bool = False,
    ) -> None:
        """Set session cookies for browser clients."""
        if not should_use_cookies(client_type):
            return

        # Set session cookie (NOT the JWT access token)
        response.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=refresh_token,  # Use refresh token as session identifier
            max_age=86400 * (30 if remember_me else 1),
            httponly=settings.SESSION_COOKIE_HTTPONLY,
            secure=settings.SESSION_COOKIE_SECURE,
            samesite=settings.SESSION_COOKIE_SAMESITE,
        )

    @staticmethod
    def clear_session_cookies(response: Response) -> None:
        """Clear all session cookies."""
        response.delete_cookie(settings.SESSION_COOKIE_NAME)
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

    @staticmethod
    def should_return_tokens(client_type: str) -> bool:
        """Determine if tokens should be returned in response body."""
        return not should_use_cookies(client_type)
