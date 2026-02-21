# pico-auth

Minimal JWT auth server built on the pico-framework stack (pico-ioc, pico-boot, pico-fastapi, pico-sqlalchemy).

## Commands

```bash
pip install -e ".[dev]"          # Install in dev mode
pytest tests/ -v                 # Run tests
pytest --cov=pico_auth --cov-report=term-missing tests/  # Coverage
tox                              # Full matrix (3.11-3.13)
ruff check pico_auth/ tests/     # Lint
python -m pico_auth.main         # Run server (port 8100)
```

## Project Structure

```
pico_auth/
  __init__.py          # Package exports
  config.py            # AuthSettings (@configured, prefix="auth")
  errors.py            # Error hierarchy (AuthError base)
  jwt_provider.py      # RS256 JWT creation/validation, JWKS, OIDC discovery
  local_auth_configurer.py # Compatibility patches for pico-client-auth + pico-fastapi
  local_jwks_provider.py  # Local JWKS provider (avoids HTTP self-call)
  main.py              # Entrypoint: create_container() + uvicorn server
  models.py            # SQLAlchemy entities: User, RefreshToken, Group, GroupMember
  passwords.py         # Bcrypt hashing service
  repository.py        # UserRepository, RefreshTokenRepository, GroupRepository
  routes.py            # AuthController (/api/v1/auth), GroupController (/api/v1/groups), OIDCController (/.well-known)
  schema.py            # create_tables() helper
  service.py           # AuthService, GroupService: register, login, refresh, profile, roles, group CRUD
tests/
  conftest.py          # Fixtures: container, app, client (in-memory SQLite)
  test_auth_e2e.py     # Full HTTP flow tests (27 tests)
  test_coverage_gaps.py # Coverage gap tests (24 tests)
application.yaml       # Default config (SQLite, port 8100, auto admin)
```

## Key Concepts

- **DI wiring**: All components use `@component` from pico-ioc. `AuthSettings` uses `@configured(prefix="auth", mapping="tree")`.
- **Routes**: `@controller(prefix="/api/v1/auth")` for auth endpoints, `@controller(prefix="/.well-known")` for OIDC.
- **JWT**: RS256 with auto-generated RSA keys stored in `~/.pico-auth/`. Keys are PEM files created on first run.
- **Refresh tokens**: Stored as SHA-256 hashes. Rotation on use (old deleted, new created).
- **Roles**: `superadmin`, `org_admin`, `operator`, `viewer`. Admin endpoints require `superadmin` or `org_admin`.
- **Password hashing**: Direct bcrypt with 72-byte truncation.
- **Groups**: `Group`, `GroupMember` entities. `GroupRepository` for data access. `GroupService` for business logic. `GroupController` at `/api/v1/groups`. Groups are included in JWT `groups` claim.
- **Auth middleware**: pico-client-auth provides `@allow_anonymous`, `@requires_role`, `@requires_group`, `SecurityContext`. `LocalJWKSProvider` reads keys locally to avoid HTTP self-call.
- **Bootstrap**: `pico_boot.init(modules=["pico_auth"])` with `YamlTreeSource` + `EnvSource`.

## Code Style

- Python 3.11+
- Flat package layout (`pico_auth/`, not `src/pico_auth/`)
- Clean separation: config -> models -> repository -> service -> routes
- All async (aiosqlite, async SQLAlchemy sessions)
- Auth/authz errors: HTTP 401/403 with `{"detail": "..."}` (via pico-client-auth middleware)
- Business logic errors: HTTP 200 with `{"error": "..."}` (e.g. duplicate email, wrong password, invalid role)

## Testing

- pytest + pytest-asyncio (strict mode)
- Full E2E via httpx `AsyncClient` with ASGI transport
- In-memory SQLite per test via `tmp_path`
- Container fixture builds real pico-ioc container with test config

## Boundaries

- This is an APPLICATION, not a library -- it runs as a standalone server
- Do not publish to PyPI
- Do not add framework-level abstractions -- use pico-* packages as-is
- Keep routes thin -- business logic lives in AuthService
- Do not store raw refresh tokens -- always hash with SHA-256
