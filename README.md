# Platform Authorization Next

Modern authorization service built with FastAPI, Pydantic, and PostgreSQL.

## Features

### 🔐 Multi-Strategy Authentication
- **Browser Sessions**: Secure cookie-based sessions with CSRF protection
- **JWT Tokens**: Short-lived access tokens + refresh rotation for mobile/API clients
- **API Keys**: Scoped API keys for machine-to-machine authentication
- **OAuth Integration**: Support for Google, GitHub, and other providers

### 🏢 Multi-Tenant Architecture  
- **Organizations**: Tenant isolation with role-based access control
- **Memberships**: User-organization relationships with roles (owner, admin, editor, viewer)
- **Policies**: Declarative authorization with guard helpers

### 🛡️ Security First
- **CSRF Protection**: Double-submit cookies for browser clients
- **Rate Limiting**: Redis-based sliding window algorithm
- **Session Management**: Device tracking, session rotation, and secure revocation
- **Password Security**: Bcrypt hashing with strength validation

### 📊 Modern Architecture
- **FastAPI**: High-performance async Python framework
- **Pydantic**: Type-safe data validation and serialization
- **SQLAlchemy 2.0**: Modern async ORM with type hints
- **Redis**: Session storage and rate limiting
- **Alembic**: Database migrations

## Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis 6+

### Installation

1. **Clone and setup:**
```bash
cd platform-authorization-next
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
```

2. **Environment Configuration:**
```bash
cp env.example .env
# Edit .env with your database and Redis URLs
```

3. **Generate JWT Keys:**
```bash
mkdir keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

4. **Database Setup:**
```bash
alembic upgrade head
```

5. **Run the application:**
```bash
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000` with interactive docs at `/api/v1/docs`.

## Architecture Overview

### Authentication Flow

#### Browser Clients (React/Vue/etc.)
```
1. Login with email/password
2. Receive encrypted session cookie
3. CSRF token in cookie + header
4. Automatic session refresh
```

#### Mobile/API Clients
```
1. Login with email/password  
2. Receive JWT access + refresh tokens
3. Access token in Authorization header
4. Refresh token rotation on expiry
```

#### Machine Clients  
```
1. Generate API key with scopes
2. Include X-API-Key header
3. Rate limiting by key
```

### Authorization System

The authorization system uses a policy-based approach with guard helpers:

```python
from app.policies import can, require, Action

# Check permissions
if can(user, Action.UPDATE, "document", resource=doc, organization_id=org.id):
    # User can update document
    pass

# Require permissions (raises exception if denied)
require(user, Action.DELETE, "user", user_id=target_user.id, organization_id=org.id)
```

#### Role Hierarchy
- **Owner**: Full access including billing and org deletion
- **Admin**: Full access except billing and org deletion  
- **Editor**: Can create/edit content and manage users
- **Viewer**: Read-only access

### Database Schema

```
users                    organizations           sessions
├── id                  ├── id                  ├── id  
├── email               ├── name                ├── user_id (FK)
├── password_hash       ├── slug                ├── session_id
├── first_name          ├── is_active           ├── refresh_token_hash
├── last_name           ├── plan                ├── expires_at
├── is_active           └── max_users           ├── device_info
└── is_verified                                 └── last_seen_at

memberships             api_keys                oauth_identities
├── id                  ├── id                  ├── id
├── user_id (FK)        ├── user_id (FK)        ├── user_id (FK)  
├── organization_id (FK)├── key_hash            ├── provider
├── role               ├── scopes              ├── provider_user_id
└── is_active          └── last_used_at        └── access_token
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Email/password login
- `POST /api/v1/auth/refresh` - Refresh access token  
- `POST /api/v1/auth/logout` - Logout current session
- `POST /api/v1/auth/logout-all` - Logout all sessions
- `GET /api/v1/auth/me` - Get current user info

### Users
- `GET /api/v1/users/` - List users in organization
- `GET /api/v1/users/{id}` - Get user details
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Deactivate user

### Organizations  
- `GET /api/v1/organizations/` - List user's organizations
- `POST /api/v1/organizations/` - Create organization
- `GET /api/v1/organizations/{id}` - Get organization details
- `PUT /api/v1/organizations/{id}` - Update organization
- `GET /api/v1/organizations/{id}/members` - List members

### Sessions
- `GET /api/v1/sessions/` - List user sessions
- `DELETE /api/v1/sessions/{id}` - Revoke specific session
- `DELETE /api/v1/sessions/other` - Revoke all other sessions

## Security Features

### Session Security
- HttpOnly cookies for browsers
- SameSite protection against CSRF
- Secure flag in production
- Device fingerprinting
- Session rotation on refresh

### Token Security  
- RS256 JWT signatures
- Short-lived access tokens (15 min)
- Refresh token rotation
- Automatic revocation on suspicious activity

### Rate Limiting
- Redis-based sliding window
- Per-IP, per-user, and per-API-key limits
- Configurable limits by client type

### CSRF Protection
- Double-submit cookie pattern
- Custom header validation
- Automatic exclusion for API clients

## Deployment

### Docker
```bash
docker build -t platform-auth .
docker run -p 8000:8000 platform-auth
```

### Environment Variables (Production)
```bash
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=your-strong-secret-key
SESSION_COOKIE_SECURE=true
DATABASE_URL=postgresql+asyncpg://...
REDIS_URL=redis://...
```

### Health Monitoring
- Health check endpoint: `GET /health`
- Process time headers
- Structured logging with correlation IDs
- Session statistics and cleanup

## Development

### Running Tests
```bash
pytest tests/ -v --cov=app
```

### Database Migrations
```bash
# Create migration
alembic revision --autogenerate -m "description"

# Apply migrations  
alembic upgrade head

# Rollback
alembic downgrade -1
```

### Code Quality
```bash
# Linting and formatting
ruff check app/
ruff format app/

# Type checking
mypy app/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
