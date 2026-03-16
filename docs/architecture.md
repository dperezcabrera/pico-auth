# Architecture

## Component Graph

```mermaid
graph TD
    A[AuthController] --> S[AuthService]
    A --> J[JWTProvider]
    O[OIDCController] --> J
    G[GroupController] --> GS[GroupService]
    S --> UR[UserRepository]
    S --> TR[RefreshTokenRepository]
    S --> GR[GroupRepository]
    S --> P[PasswordService]
    S --> J
    S --> C[AuthSettings]
    GS --> GR
    J --> C
    UR --> SM[SessionManager]
    TR --> SM
    GR --> SM
```

## Layer Separation

| Layer | Components | Responsibility |
|-------|-----------|----------------|
| **Config** | `AuthSettings` | Load settings from YAML/env |
| **Models** | `User`, `RefreshToken`, `Group`, `GroupMember` | SQLAlchemy entity definitions |
| **Repository** | `UserRepository`, `RefreshTokenRepository`, `GroupRepository` | Database access (CRUD) |
| **Service** | `AuthService`, `GroupService` | Business logic, validation |
| **Security** | `JWTProvider`, `PasswordService` | Token creation, password hashing |
| **Routes** | `AuthController`, `GroupController`, `OIDCController` | HTTP endpoints |
| **Bootstrap** | `main.py` | Container creation, server startup |

## Dependency Injection

All components are wired via pico-ioc decorators:

- `@component` - Auto-registered service/repository
- `@configured(prefix="auth", mapping="tree")` - Config from YAML
- `@controller(prefix="/api/v1/auth")` - FastAPI route class

The container is bootstrapped in `main.py`:

```python
container = init(modules=["pico_auth"], config=config)
```

## Database

- **ORM**: SQLAlchemy 2.0 async (via pico-sqlalchemy)
- **Default engine**: SQLite + aiosqlite
- **Tables**: `users`, `refresh_tokens`, `groups`, `group_members`
- **Schema creation**: `create_tables(session_manager)` on startup

## Key Storage

Keys are stored in `~/.pico-auth/` and auto-generated on first run.

**RSA (RS256):**

- `private.pem` (mode 0600) — Used for JWT signing
- `public.pem` — Used for JWT verification and JWKS endpoint

**ML-DSA (ML-DSA-65, ML-DSA-87):**

- `pqc_secret.bin` (mode 0600) — Used for JWT signing
- `pqc_public.bin` — Used for JWT verification and JWKS endpoint

The algorithm is selected via `auth.algorithm` in configuration. JWKS serves RSA keys (`kty: "RSA"`) or ML-DSA keys (`kty: "AKP"`) accordingly.
