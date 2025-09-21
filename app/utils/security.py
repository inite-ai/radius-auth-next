"""Security utilities for password hashing, token generation, etc."""

import secrets
import string
from datetime import datetime, timedelta

from passlib.context import CryptContext

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def generate_random_string(length: int = 32) -> str:
    """Generate a random string of specified length."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_api_key(prefix: str = "pauth", length: int = 32) -> str:
    """Generate an API key with prefix."""
    random_part = generate_random_string(length)
    return f"{prefix}_{random_part}"


def generate_session_id() -> str:
    """Generate a unique session ID."""
    return generate_random_string(64)


def generate_csrf_token() -> str:
    """Generate a CSRF token."""
    return generate_random_string(32)


def is_strong_password(password: str) -> bool:
    """Check if password meets strength requirements."""
    if len(password) < 8:
        return False

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    return all([has_upper, has_lower, has_digit, has_special])


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return secrets.compare_digest(a, b)


def hash_token(token: str) -> str:
    """Hash a token for storage (for refresh tokens, API keys, etc.)."""
    import hashlib

    return hashlib.sha256(token.encode()).hexdigest()


def create_expiration_time(minutes: int | None = None, days: int | None = None) -> datetime:
    """Create an expiration timestamp."""
    if minutes:
        return datetime.utcnow() + timedelta(minutes=minutes)
    elif days:
        return datetime.utcnow() + timedelta(days=days)
    else:
        return datetime.utcnow() + timedelta(hours=1)  # Default 1 hour
