# Platform Authorization Next - Architecture Plan

## Современная архитектура авторизации на FastAPI + Pydantic

### 1. Модель доступа (Organizations, Users, Roles, Permissions)

#### Основные сущности:
- **Organizations (orgs)** - тенанты/компании
- **Users** - пользователи системы
- **Memberships** - связь пользователей с организациями и ролями (user_id, org_id, role)
- **Roles** - роли: owner, admin, editor, viewer
- **Permissions** - политики доступа через код (can?(:update, :doc, ctx))

#### Политики доступа:
- Policy-модуль с guard helpers
- Примитив: ресурс принадлежит org → проверяем membership
- Чувствительные операции — явные политики
- Декораторы на контроллерах: `@authorize(action="update", resource="doc")`

### 2. AuthN - Стратегии аутентификации

#### Браузер (React):
- Cookie-сессии (signed+encrypted, httpOnly, SameSite=Lax/Strict)
- CSRF-токены для защиты от CSRF атак
- Никаких JWT в браузере

#### Мобильные приложения и интеграции:
- JWT access токены (короткие, 5-15 мин)
- Refresh токены (длинные, с ротацией)
- Безопасное хранение в keychain/keystore

#### API ключи для машин:
- Формат: `prefix_xxx...`
- Хранение хэша в БД с scope'ами
- Возможность отзыва

#### OAuth/Social (опциональный):
- Таблица `oauth_identities` (provider, uid, user_id)
- Связывание после callback

### 3. Токены и ключи

#### JWT управление:
- Подпись через PyJWT с RS256
- Ключи как JWK-сет (активный + следующий для ротации)
- `kid` в заголовке для идентификации ключа

#### Refresh ротация:
- Каждый обмен refresh→access выдаёт новый refresh
- Старый refresh немедленно инвалидируется
- Reuse detection → баним всю сессию

#### Revocation система:
- Таблица `sessions` (id, user_id, device, refresh_hash, expires_at, last_seen_at, user_agent, ip)
- "Выйти везде" = нулим все активные сессии
- Blacklist для отозванных токенов

### 4. FastAPI Pipeline

#### Middleware для разных типов клиентов:
- **Browser middleware**: session + CSRF + current_org из куки/URL
- **API middleware**: Bearer JWT → current_user/current_org в request.state
- **WebSocket middleware**: проверка токена при подключении

#### Структура проекта:
```
platform-authorization-next/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI app
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py         # Pydantic settings
│   │   └── database.py         # DB connection
│   ├── models/
│   │   ├── __init__.py
│   │   ├── base.py            # Base SQLAlchemy model
│   │   ├── user.py            # User model
│   │   ├── organization.py    # Organization model
│   │   ├── membership.py      # Membership model
│   │   ├── session.py         # Session model
│   │   ├── api_key.py         # API Key model
│   │   └── oauth_identity.py  # OAuth identity model
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── auth.py            # Auth request/response schemas
│   │   ├── user.py            # User schemas
│   │   ├── organization.py    # Organization schemas
│   │   └── common.py          # Common schemas
│   ├── services/
│   │   ├── __init__.py
│   │   ├── auth_service.py    # Authentication logic
│   │   ├── jwt_service.py     # JWT handling
│   │   ├── session_service.py # Session management
│   │   ├── policy_service.py  # Authorization policies
│   │   └── oauth_service.py   # OAuth providers
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── auth_middleware.py # Authentication middleware
│   │   ├── csrf_middleware.py # CSRF protection
│   │   └── rate_limit.py      # Rate limiting
│   ├── policies/
│   │   ├── __init__.py
│   │   ├── base_policy.py     # Base policy class
│   │   ├── user_policy.py     # User policies
│   │   └── resource_policy.py # Resource policies
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py            # Auth endpoints
│   │   ├── users.py           # User endpoints
│   │   ├── organizations.py   # Organization endpoints
│   │   └── sessions.py        # Session management
│   ├── dependencies/
│   │   ├── __init__.py
│   │   ├── auth.py            # Auth dependencies
│   │   └── database.py        # DB dependencies
│   └── utils/
│       ├── __init__.py
│       ├── security.py        # Security utilities
│       ├── exceptions.py      # Custom exceptions
│       └── validators.py      # Custom validators
├── alembic/                   # Database migrations
├── tests/                     # Test suite
├── requirements.txt           # Dependencies
├── pyproject.toml            # Project configuration
├── ruff.toml                 # Linting configuration
└── README.md                 # Documentation
```

### 5. Безопасность

#### Session Security:
- HttpOnly cookies
- Secure flag в production
- SameSite protection
- Session rotation
- Device fingerprinting

#### CSRF Protection:
- Double submit cookies
- Custom headers для API
- SameSite cookies как дополнительная защита

#### Rate Limiting:
- Per IP limits
- Per user limits
- Sliding window algorithm
- Redis для distributed rate limiting

#### Security Headers:
- HSTS
- Content Security Policy
- X-Frame-Options
- X-Content-Type-Options

### 6. Интеграция с существующими сервисами

#### Совместимость:
- Поддержка существующих API токенов (переходный период)
- Миграция пользователей из старой системы
- Обратная совместимость с WebSocket авторизацией

#### Мониторинг:
- Логирование всех auth событий
- Метрики производительности
- Alerting на подозрительную активность
- Audit trail для sensitive operations
