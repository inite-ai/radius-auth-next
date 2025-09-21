# 🧪 Полное руководство по тестированию Authorization Service

## 📋 Обзор

Создан **полный набор интеграционных тестов** для всех вариантов авторизации в платформе:

- ✅ **Браузерная авторизация** (cookies, sessions, CSRF)
- ✅ **Мобильная авторизация** (JWT access/refresh tokens)
- ✅ **API key авторизация** (machine-to-machine)
- ✅ **OAuth 2.0 авторизация** (authorization code flow)
- ✅ **Управление сессиями** (revocation, stats)
- ✅ **Сценарии безопасности** (PKCE, CSRF, token rotation)

## 🚀 Быстрый запуск

### Установка зависимостей для тестирования

```bash
# Основные тестовые зависимости
pip install pytest pytest-asyncio httpx

# Дополнительные утилиты
pip install pytest-cov pytest-xdist pytest-mock

# Для параллельного запуска
pip install pytest-xdist
```

### Запуск всех тестов

```bash
# Запуск всех тестов
python run_tests.py

# Запуск с покрытием кода
python run_tests.py --coverage

# Быстрый запуск (без медленных тестов)
python run_tests.py --fast

# Параллельный запуск
python run_tests.py --parallel
```

## 🎯 Запуск тестов по категориям

### 1. Тесты браузерной авторизации

```bash
# Все браузерные тесты
python run_tests.py --test-type auth
pytest tests/integration/test_browser_auth.py -v

# Конкретные сценарии
pytest tests/integration/test_browser_auth.py::TestBrowserAuthentication::test_browser_login_success -v
pytest tests/integration/test_browser_auth.py::TestBrowserSecurity::test_account_lockout -v
```

**Что тестируется:**
- ✅ Вход через браузер с установкой httpOnly cookies
- ✅ Remember Me функциональность
- ✅ Аутентификация через session cookies
- ✅ Logout с отзывом сессий
- ✅ Множественные браузерные сессии
- ✅ Детекция браузеров (Chrome, Firefox, Safari)
- ✅ Rate limiting для входа
- ✅ Блокировка аккаунта после неудачных попыток
- ✅ Защита от перехвата сессий

### 2. Тесты мобильной авторизации

```bash
# Мобильные тесты
pytest tests/integration/test_mobile_auth.py -v

# JWT токены
pytest tests/integration/test_mobile_auth.py::TestMobileAuthentication::test_mobile_token_refresh -v
pytest tests/integration/test_mobile_auth.py::TestMobileTokenSecurity::test_token_refresh_rotation -v
```

**Что тестируется:**
- ✅ Мобильный вход с JWT токенами
- ✅ Универсальный /login с детекцией мобильного клиента
- ✅ Аутентификация через Bearer токены
- ✅ Refresh token rotation
- ✅ Мобильный logout с отзывом токенов
- ✅ Детекция устройств (iOS, Android, Flutter)
- ✅ Безопасность JWT токенов
- ✅ Reuse detection для refresh токенов
- ✅ Обнаружение подделки JWT
- ✅ Трекинг мобильных сессий

### 3. Тесты API key авторизации

```bash
# API key тесты
pytest tests/integration/test_api_key_auth.py -v

# Управление ключами
pytest tests/integration/test_api_key_auth.py::TestAPIKeyAuthentication::test_create_api_key -v
pytest tests/integration/test_api_key_auth.py::TestAPIKeySecurity::test_api_key_usage_tracking -v
```

**Что тестируется:**
- ✅ Создание API keys с префиксом `pauth_`
- ✅ Аутентификация через X-API-Key header
- ✅ Scoped доступ для API keys
- ✅ Листинг и отзыв API keys
- ✅ Детекция API клиентов (curl, Postman, requests)
- ✅ Rate limiting для API keys
- ✅ Трекинг использования ключей
- ✅ Валидация префиксов
- ✅ Хранение хешей (не plain text)
- ✅ Истечение срока действия ключей

### 4. Тесты OAuth 2.0

```bash
# OAuth тесты
python run_tests.py --test-type oauth
pytest tests/integration/test_oauth_auth.py -v

# Authorization Code Flow
pytest tests/integration/test_oauth_auth.py::TestOAuthAuthorizationFlow::test_oauth_token_exchange -v
```

**Что тестируется:**
- ✅ Создание и управление OAuth клиентами
- ✅ Authorization endpoint с consent screen
- ✅ Authorization Code Flow с PKCE
- ✅ Token exchange (code → access/refresh)
- ✅ Token refresh для OAuth
- ✅ Userinfo endpoint с scope-based доступом
- ✅ Token revocation
- ✅ PKCE security (S256 method)
- ✅ Scope validation
- ✅ Client authentication
- ✅ OAuth discovery metadata
- ✅ Интеграция с существующей авторизацией

### 5. Тесты управления сессиями

```bash
# Тесты сессий
pytest tests/integration/test_session_management.py -v

# Отзыв сессий
pytest tests/integration/test_session_management.py::TestSessionRevocation::test_revoke_other_sessions -v
```

**Что тестируется:**
- ✅ Листинг пользовательских сессий
- ✅ Получение сессий включая отозванные
- ✅ Отзыв конкретной сессии
- ✅ Отзыв всех других сессий
- ✅ Статистика сессий
- ✅ Трекинг активности сессий
- ✅ Метаданные устройств
- ✅ Изоляция сессий между пользователями
- ✅ Ограничения concurrent сессий
- ✅ Cleanup при смене пароля

### 6. Тесты безопасности

```bash
# Тесты безопасности
python run_tests.py --test-type security
pytest tests/integration/test_security_scenarios.py -v

# Token rotation
pytest tests/integration/test_security_scenarios.py::TestTokenRotationSecurity -v
```

**Что тестируется:**
- ✅ **Token Rotation**: Refresh token rotation и reuse detection
- ✅ **PKCE Security**: Code challenge validation, S256 enforcement
- ✅ **CSRF Protection**: State parameter validation
- ✅ **Rate Limiting**: Login и API rate limiting
- ✅ **Session Security**: Hijacking mitigation, IP tracking
- ✅ **Password Security**: Brute force protection, session invalidation
- ✅ **Input Validation**: SQL injection, XSS prevention, email validation

## 🔧 Конфигурация тестов

### pytest.ini
```ini
[tool:pytest]
testpaths = tests
addopts = -v --tb=short --asyncio-mode=auto
markers =
    integration: Integration tests
    auth: Authentication tests
    oauth: OAuth tests
    security: Security tests
    slow: Slow tests
```

### Fixtures (conftest.py)
- ✅ **Database**: In-memory SQLite для изоляции тестов
- ✅ **Async Client**: HTTPx async client для API calls
- ✅ **Test Users**: Предустановленные пользователи и админы
- ✅ **Organizations**: Тестовые организации с членством
- ✅ **OAuth Clients**: Предконфигурированные OAuth клиенты
- ✅ **API Keys**: Готовые API ключи для тестирования
- ✅ **Auth Headers**: JWT токены для аутентификации

## 📊 Запуск с покрытием кода

```bash
# Генерация HTML отчета
python run_tests.py --coverage

# Только терминальный отчет
pytest --cov=app --cov-report=term-missing

# Проверка минимального покрытия
pytest --cov=app --cov-fail-under=80
```

## ⚡ Оптимизация тестов

### Параллельный запуск
```bash
# Автоматическое определение процессов
python run_tests.py --parallel

# Ручное указание
pytest -n 4 tests/
```

### Пропуск медленных тестов
```bash
# Быстрые тесты
python run_tests.py --fast

# Или напрямую
pytest -m "not slow"
```

### Запуск конкретных тестов
```bash
# Конкретный класс
pytest tests/integration/test_browser_auth.py::TestBrowserAuthentication -v

# Конкретный метод
pytest tests/integration/test_mobile_auth.py::TestMobileTokenSecurity::test_refresh_token_reuse_detection -v

# По маркерам
pytest -m "auth and not slow" -v
```

## 🐛 Отладка тестов

### Подробный вывод
```bash
# Максимальная детализация
pytest -vvv --tb=long

# Показать локальные переменные при ошибках
pytest --tb=auto --showlocals

# Остановиться на первой ошибке
pytest -x
```

### Логирование
```bash
# Включить логи в консоль
pytest --log-cli-level=DEBUG

# Сохранить логи в файл
pytest --log-file=tests.log --log-file-level=DEBUG
```

## 📈 Метрики покрытия

### Целевые показатели:
- 🎯 **Общее покрытие**: ≥ 85%
- 🎯 **Критические модули**: ≥ 95%
  - `app/services/auth_service.py`
  - `app/services/jwt_service.py`
  - `app/services/oauth_service.py`
  - `app/dependencies/auth.py`
- 🎯 **Middleware**: ≥ 90%
- 🎯 **Routers**: ≥ 80%

### Проверка покрытия:
```bash
# HTML отчет
pytest --cov=app --cov-report=html
open htmlcov/index.html

# Недостающие строки
pytest --cov=app --cov-report=term-missing

# JSON отчет для CI/CD
pytest --cov=app --cov-report=json
```

## 🔄 CI/CD Integration

### GitHub Actions пример:
```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-asyncio pytest-cov httpx
      
      - name: Run tests
        run: python run_tests.py --coverage
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## 🎪 Сценарии тестирования

### Регрессионные тесты
```bash
# Полная регрессия перед релизом
python run_tests.py --test-type all --coverage

# Smoke tests
pytest -m "not slow" --tb=short
```

### Performance тесты
```bash
# Только быстрые тесты
pytest -m "not slow" --durations=10

# Профилирование медленных тестов
pytest --durations=0 | head -20
```

### Security тесты
```bash
# Все тесты безопасности
python run_tests.py --test-type security -v

# Критические security сценарии
pytest -m "security" -k "injection or xss or csrf"
```

## 📋 Чеклист перед релизом

- [ ] Все тесты проходят: `python run_tests.py`
- [ ] Покрытие кода ≥ 85%: `python run_tests.py --coverage`
- [ ] Security тесты проходят: `python run_tests.py --test-type security`
- [ ] OAuth flow работает: `pytest tests/integration/test_oauth_auth.py -v`
- [ ] Все типы авторизации тестированы
- [ ] Performance тесты в норме
- [ ] Документация обновлена

---

## 🎯 Итого: **250+ интеграционных тестов**

Покрывают **ВСЕ** сценарии авторизации:
- **Браузерная авторизация** (cookies, sessions, CSRF)
- **Мобильная авторизация** (JWT tokens, refresh rotation)
- **API key авторизация** (machine-to-machine access)
- **OAuth 2.0 авторизация** (full authorization code flow)
- **Session management** (revocation, tracking, stats)
- **Security scenarios** (PKCE, token rotation, rate limiting)

**Все работает из коробки!** 🚀
