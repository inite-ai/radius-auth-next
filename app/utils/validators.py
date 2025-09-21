"""Validation utilities."""

import re

from email_validator import EmailNotValidError
from email_validator import validate_email as _validate_email

from .exceptions import ValidationError


def validate_email(email: str) -> str:
    """Validate and normalize email address."""
    try:
        validated_email = _validate_email(email)
        return validated_email.email
    except EmailNotValidError as e:
        raise ValidationError(f"Invalid email address: {e}")


def validate_password(password: str) -> None:
    """Validate password strength."""
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    if len(password) > 128:
        errors.append("Password must be less than 128 characters")

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")

    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")

    if errors:
        raise ValidationError("Password validation failed", details={"errors": errors})


def validate_username(username: str) -> None:
    """Validate username format."""
    if not username:
        raise ValidationError("Username is required")

    if len(username) < 3:
        raise ValidationError("Username must be at least 3 characters long")

    if len(username) > 30:
        raise ValidationError("Username must be less than 30 characters")

    # Username can contain letters, numbers, underscores, and hyphens
    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        raise ValidationError(
            "Username can only contain letters, numbers, underscores, and hyphens"
        )

    # Username cannot start or end with underscore or hyphen
    if username.startswith(("_", "-")) or username.endswith(("_", "-")):
        raise ValidationError("Username cannot start or end with underscore or hyphen")


def validate_organization_slug(slug: str) -> None:
    """Validate organization slug format."""
    if not slug:
        raise ValidationError("Organization slug is required")

    if len(slug) < 3:
        raise ValidationError("Organization slug must be at least 3 characters long")

    if len(slug) > 50:
        raise ValidationError("Organization slug must be less than 50 characters")

    # Slug can contain lowercase letters, numbers, and hyphens
    if not re.match(r"^[a-z0-9-]+$", slug):
        raise ValidationError(
            "Organization slug can only contain lowercase letters, numbers, and hyphens"
        )

    # Slug cannot start or end with hyphen
    if slug.startswith("-") or slug.endswith("-"):
        raise ValidationError("Organization slug cannot start or end with hyphen")

    # Reserved slugs
    reserved_slugs = [
        "api",
        "www",
        "mail",
        "admin",
        "root",
        "blog",
        "help",
        "support",
        "billing",
        "payments",
        "auth",
        "login",
        "signup",
        "dashboard",
        "settings",
        "profile",
        "account",
        "organization",
        "org",
        "team",
    ]

    if slug in reserved_slugs:
        raise ValidationError(f"Organization slug '{slug}' is reserved")


def validate_phone_number(phone: str) -> None:
    """Validate phone number format."""
    if not phone:
        return  # Phone is optional

    # Remove all non-digit characters
    digits_only = re.sub(r"\D", "", phone)

    # Check length (7-15 digits is standard for international numbers)
    if len(digits_only) < 7 or len(digits_only) > 15:
        raise ValidationError("Phone number must be between 7 and 15 digits")


def validate_timezone(timezone: str) -> None:
    """Validate timezone string."""
    if not timezone:
        return  # Timezone is optional

    try:
        import pytz

        pytz.timezone(timezone)
    except Exception:
        raise ValidationError(f"Invalid timezone: {timezone}")


def validate_locale(locale: str) -> None:
    """Validate locale string."""
    if not locale:
        return  # Locale is optional

    # Basic locale format validation (e.g., en-US, fr-FR)
    if not re.match(r"^[a-z]{2}(-[A-Z]{2})?$", locale):
        raise ValidationError("Locale must be in format 'xx' or 'xx-XX' (e.g., 'en' or 'en-US')")


def validate_hex_color(color: str) -> None:
    """Validate hex color format."""
    if not color:
        return  # Color is optional

    if not re.match(r"^#[0-9a-fA-F]{6}$", color):
        raise ValidationError("Color must be a valid hex color (e.g., #FF0000)")


def validate_url(url: str) -> None:
    """Validate URL format."""
    if not url:
        return  # URL is optional

    url_pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
        r"localhost|"  # localhost...
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )

    if not url_pattern.match(url):
        raise ValidationError("Invalid URL format")
