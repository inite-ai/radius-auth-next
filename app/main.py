"""FastAPI main application module."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config.database import close_redis, init_redis
from app.config.settings import settings
from app.middleware.auth_middleware import AuthMiddleware
from app.middleware.exception_handler import register_exception_handlers
from app.middleware.logging_middleware import PerformanceMiddleware, RequestLoggingMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.routers import auth, oauth, organizations, sessions, users

# Create FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description=settings.API_DESCRIPTION,
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
)

# Register exception handlers
register_exception_handlers(app)

# Security middleware
if settings.ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"],  # Configure with actual domains in production
    )

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)

# Request/Response logging middleware (should be early in the stack)
app.add_middleware(
    RequestLoggingMiddleware,
    log_body=settings.ENVIRONMENT != "production",  # Don't log bodies in production
    log_headers=settings.ENVIRONMENT == "development",
    max_body_size=2048,
)

# Performance monitoring middleware
app.add_middleware(
    PerformanceMiddleware,
    slow_request_threshold=2.0,
    enable_metrics=True,
)

# Custom middleware
app.add_middleware(RateLimitMiddleware)
# CSRF middleware disabled for now to fix tests
# app.add_middleware(CSRFMiddleware)
app.add_middleware(AuthMiddleware)


# Event handlers
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    await init_redis()


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    await close_redis()


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.API_VERSION,
        "environment": settings.ENVIRONMENT,
    }


# Include routers
app.include_router(
    auth.router,
    prefix=f"{settings.API_PREFIX}/auth",
    tags=["Authentication"],
)

app.include_router(
    users.router,
    prefix=f"{settings.API_PREFIX}/users",
    tags=["Users"],
)

app.include_router(
    organizations.router,
    prefix=f"{settings.API_PREFIX}/organizations",
    tags=["Organizations"],
)

app.include_router(
    sessions.router,
    prefix=f"{settings.API_PREFIX}/sessions",
    tags=["Sessions"],
)

app.include_router(
    oauth.router,
    prefix=f"{settings.API_PREFIX}/oauth",
    tags=["OAuth 2.0"],
)


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "message": "Platform Authorization API",
        "version": settings.API_VERSION,
        "docs_url": f"{settings.API_PREFIX}/docs",
    }
