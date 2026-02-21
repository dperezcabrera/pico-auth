# Pico-Auth

[![PyPI](https://img.shields.io/pypi/v/pico-auth.svg)](https://pypi.org/project/pico-auth/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/dperezcabrera/pico-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
![CI (tox matrix)](https://github.com/dperezcabrera/pico-auth/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dperezcabrera/pico-auth/branch/main/graph/badge.svg)](https://codecov.io/gh/dperezcabrera/pico-auth)
[![Docs](https://img.shields.io/badge/Docs-pico--auth-blue?style=flat&logo=readthedocs&logoColor=white)](https://dperezcabrera.github.io/pico-auth/)

**Minimal JWT auth server for the Pico ecosystem.**

Pico-Auth is a ready-to-run authentication server built on top of the [pico-framework](https://github.com/dperezcabrera/pico-ioc) stack. It provides:

- **RS256 JWT tokens** with auto-generated RSA key pairs
- **Refresh token rotation** with SHA-256 hashed storage
- **RBAC** with four built-in roles: `superadmin`, `org_admin`, `operator`, `viewer`
- **Group management** with CRUD API, membership, and `groups` JWT claim
- **OIDC discovery** endpoints (`.well-known/openid-configuration`, JWKS)
- **Bcrypt password hashing** (72-byte input limit enforced)
- **Zero-config startup** with auto-created admin user

> Requires Python 3.11+

---

## Architecture

Pico-Auth uses the full Pico stack with dependency injection:

| Layer | Component | Decorator |
|-------|-----------|-----------|
| Config | `AuthSettings` | `@configured(prefix="auth")` |
| Models | `User`, `RefreshToken`, `Group`, `GroupMember` | SQLAlchemy `AppBase` |
| Repository | `UserRepository`, `RefreshTokenRepository`, `GroupRepository` | `@component` |
| Service | `AuthService`, `GroupService` | `@component` |
| Security | `JWTProvider`, `PasswordService`, `LocalJWKSProvider` | `@component` |
| Routes | `AuthController`, `GroupController`, `OIDCController` | `@controller` |

---

## Installation

```bash
pip install -e ".[dev]"
```

---

## Quick Start

### 1. Run the Server

```bash
python -m pico_auth.main
```

The server starts on `http://localhost:8100` with:
- An auto-created admin user (`admin@pico.local` / `admin`)
- SQLite database at `auth.db`
- RSA keys at `~/.pico-auth/`

### 2. Register a User

```bash
curl -X POST http://localhost:8100/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123", "display_name": "Alice"}'
```

### 3. Login

```bash
curl -X POST http://localhost:8100/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

Returns:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "a1b2c3d4...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### 4. Access Protected Endpoint

```bash
curl http://localhost:8100/api/v1/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/auth/register` | No | Register a new user |
| POST | `/api/v1/auth/login` | No | Login and get tokens |
| POST | `/api/v1/auth/refresh` | No | Refresh access token |
| GET | `/api/v1/auth/me` | Bearer | Get current user profile |
| POST | `/api/v1/auth/me/password` | Bearer | Change password |
| GET | `/api/v1/auth/users` | Admin | List all users |
| PUT | `/api/v1/auth/users/{id}/role` | Admin | Update user role |
| GET | `/api/v1/auth/jwks` | No | JSON Web Key Set |
| POST | `/api/v1/groups` | Admin | Create a group |
| GET | `/api/v1/groups` | Bearer | List groups (by org) |
| GET | `/api/v1/groups/{id}` | Bearer | Get group with members |
| PUT | `/api/v1/groups/{id}` | Admin | Update group |
| DELETE | `/api/v1/groups/{id}` | Admin | Delete group |
| POST | `/api/v1/groups/{id}/members` | Admin | Add member to group |
| DELETE | `/api/v1/groups/{id}/members/{uid}` | Admin | Remove member |
| GET | `/.well-known/openid-configuration` | No | OIDC discovery |

---

## Configuration

All settings are loaded from `application.yaml` and can be overridden with environment variables:

```yaml
auth:
  data_dir: "~/.pico-auth"              # RSA key storage
  access_token_expire_minutes: 15        # JWT lifetime
  refresh_token_expire_days: 7           # Refresh token lifetime
  issuer: "http://localhost:8100"        # JWT issuer claim
  audience: "pico-bot"                   # JWT audience claim
  auto_create_admin: true                # Create admin on startup
  admin_email: "admin@pico.local"        # Default admin email
  admin_password: "admin"                # Default admin password

database:
  url: "sqlite+aiosqlite:///auth.db"     # Database URL
  echo: false                            # SQL logging

auth_client:
  enabled: true                          # Enable auth middleware
  issuer: "http://localhost:8100"        # Must match auth.issuer
  audience: "pico-bot"                   # Must match auth.audience

fastapi:
  title: "Pico Auth API"
  version: "0.1.0"
```

Environment variable override example:
```bash
AUTH_ISSUER=https://auth.myapp.com AUTH_ADMIN_PASSWORD=strong-password python -m pico_auth.main
```

---

## JWT Token Claims

Access tokens include:

| Claim | Description |
|-------|-------------|
| `sub` | User ID |
| `email` | User email |
| `role` | User role (`superadmin`, `org_admin`, `operator`, `viewer`) |
| `org_id` | Organization ID |
| `groups` | Group IDs the user belongs to |
| `iss` | Issuer URL |
| `aud` | Audience |
| `iat` | Issued at (Unix timestamp) |
| `exp` | Expiration (Unix timestamp) |
| `jti` | Unique token ID |

---

## Ecosystem

Pico-Auth is built on:

| Package | Role |
|---------|------|
| [pico-ioc](https://github.com/dperezcabrera/pico-ioc) | Dependency injection container |
| [pico-boot](https://github.com/dperezcabrera/pico-boot) | Bootstrap and plugin discovery |
| [pico-fastapi](https://github.com/dperezcabrera/pico-fastapi) | FastAPI integration with `@controller` |
| [pico-sqlalchemy](https://github.com/dperezcabrera/pico-sqlalchemy) | Async SQLAlchemy with `SessionManager` |
| [pico-client-auth](https://github.com/dperezcabrera/pico-client-auth) | JWT auth middleware with `SecurityContext` |

---

## Development

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest --cov=pico_auth --cov-report=term-missing tests/

# Full test matrix
tox

# Lint
ruff check pico_auth/ tests/
```

---

## License

MIT - [LICENSE](./LICENSE)
