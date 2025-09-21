"""Application configuration using Pydantic settings."""

from pathlib import Path

from pydantic import AnyHttpUrl, Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # API Configuration
    API_TITLE: str = "Platform Authorization API"
    API_VERSION: str = "1.0.0"
    API_DESCRIPTION: str = "Modern authorization service with multi-tenant support"
    API_PREFIX: str = "/api/v1"

    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    TESTING: bool = False

    # Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./test.db", description="Async PostgreSQL database URL"
    )
    DATABASE_URL_SYNC: str = Field(
        default="sqlite:///./test.db", description="Sync PostgreSQL database URL for migrations"
    )

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Security
    SECRET_KEY: str = Field(
        default="test-secret-key-super-long-for-testing-purposes-only-change-in-production",
        min_length=32,
        description="Secret key for general encryption",
    )

    # JWT Configuration
    JWT_SECRET_KEY: str = Field(
        default="test-jwt-secret-key-super-long-for-testing-purposes-only",
        min_length=32,
        description="Secret key for JWT tokens",
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    JWT_PRIVATE_KEY_PATH: Path = Path("keys/private.pem")
    JWT_PUBLIC_KEY_PATH: Path = Path("keys/public.pem")

    @property
    def JWT_PRIVATE_KEY(self) -> str:
        """Load JWT private key from file."""
        if self.JWT_PRIVATE_KEY_PATH.exists():
            return self.JWT_PRIVATE_KEY_PATH.read_text()
        return ""

    @property
    def JWT_PUBLIC_KEY(self) -> str:
        """Load JWT public key from file."""
        if self.JWT_PUBLIC_KEY_PATH.exists():
            return self.JWT_PUBLIC_KEY_PATH.read_text()
        return ""

    # Session Configuration
    SESSION_SECRET_KEY: str = Field(
        default="test-session-secret-key-super-long-for-testing-purposes-only",
        min_length=32,
        description="Secret key for session encryption",
    )
    SESSION_COOKIE_NAME: str = "platform_session"
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = False  # Set to True in production
    SESSION_COOKIE_SAMESITE: str = "lax"
    SESSION_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # CSRF Configuration
    CSRF_SECRET_KEY: str = Field(
        default="test-csrf-secret-key-super-long-for-testing-purposes-only-change",
        min_length=32,
        description="Secret key for CSRF tokens",
    )
    CSRF_TOKEN_EXPIRE_MINUTES: int = 60
    CSRF_HEADER_NAME: str = "X-CSRF-Token"
    CSRF_COOKIE_NAME: str = "csrf_token"

    # Rate Limiting
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    RATE_LIMIT_BURST_SIZE: int = 10

    # CORS
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8080"]
    ALLOWED_METHODS: list[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    ALLOWED_HEADERS: list[str] = ["*"]

    # OAuth Configuration (optional)
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GITHUB_CLIENT_ID: str | None = None
    GITHUB_CLIENT_SECRET: str | None = None

    # Monitoring
    LOG_LEVEL: str = "INFO"
    SENTRY_DSN: str | None = None

    # API Keys
    API_KEY_PREFIX: str = "pauth_"
    API_KEY_LENGTH: int = 32

    # Password Policy
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    PASSWORD_REQUIRE_LOWERCASE: bool = True
    PASSWORD_REQUIRE_DIGITS: bool = True
    PASSWORD_REQUIRE_SPECIAL: bool = True

    # Account Settings
    EMAIL_VERIFICATION_REQUIRED: bool = True
    ACCOUNT_LOCKOUT_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 30

    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        """Validate environment setting."""
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of: {allowed}")
        return v

    @validator("SESSION_COOKIE_SECURE")
    def validate_secure_cookie_in_production(cls, v, values):
        """Ensure secure cookies in production."""
        if values.get("ENVIRONMENT") == "production" and not v:
            raise ValueError("SESSION_COOKIE_SECURE must be True in production")
        return v

    @validator("ALLOWED_ORIGINS")
    def validate_origins(cls, v):
        """Validate CORS origins."""
        validated_origins = []
        for origin in v:
            if origin == "*":
                validated_origins.append(origin)
            else:
                # Validate as HTTP URL
                try:
                    AnyHttpUrl(origin)
                    validated_origins.append(origin)
                except Exception:
                    raise ValueError(f"Invalid origin URL: {origin}")
        return validated_origins

    class Config:
        """Pydantic config."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()
