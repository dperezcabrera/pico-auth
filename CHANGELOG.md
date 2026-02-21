# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.html).

---

## v0.2.0 — Group Management (2026-02-21)

### Added

- **Group CRUD API** — 7 endpoints at `/api/v1/groups` for creating, listing, updating, deleting groups and managing membership
- **`groups` JWT claim** — Login and refresh tokens now include group IDs for the authenticated user
- **`Group` entity** — SQLAlchemy model with `id`, `name`, `description`, `org_id`, timestamps
- **`GroupMember` entity** — Composite-key model linking users to groups
- **`GroupRepository`** — Data access for groups and group membership
- **`GroupService`** — Business logic for group CRUD and member management
- **`GroupController`** — REST controller at `/api/v1/groups`
- **`@requires_group` forwarding** — `LocalAuthConfigurer` forwards the decorator from pico-client-auth
- Error types: `GroupNotFoundError`, `GroupExistsError`, `MemberAlreadyInGroupError`, `MemberNotInGroupError`
- Docker E2E test infrastructure (`Dockerfile.test`, `Makefile`)

### Changed

- Aligned ruff config with ecosystem (C901, PLR1702, preview mode)
- `timezone.utc` replaced with `datetime.UTC`

---

## v0.1.3 — Remove Configurer Guard Patch (2026-02-20)

### Removed
- **DatabaseConfigurer guard patch**: Removed the monkeypatch in `local_auth_configurer.py` that guarded `AuthFastapiConfigurer.configure()` against non-FastAPI calls. No longer needed after the protocol method rename in pico-sqlalchemy and pico-fastapi.

---

## v0.1.0 — Initial Release (2026-02-20)

### Added
- **Registration** endpoint with email uniqueness validation.
- **Login** endpoint returning RS256 JWT access token and opaque refresh token.
- **Refresh token rotation** with SHA-256 hashed storage — old tokens invalidated on use.
- **Profile** endpoint (`GET /me`) returning user details from JWT claims.
- **Change password** endpoint with old-password verification and token revocation.
- **Admin endpoints**: list users, update user roles (requires `superadmin` or `org_admin`).
- **RBAC** with four built-in roles: `superadmin`, `org_admin`, `operator`, `viewer`.
- **OIDC discovery**: `/.well-known/openid-configuration` and `/api/v1/auth/jwks`.
- **Auto-generated RSA key pair** stored as PEM files in configurable data directory.
- **Auto-created admin user** on first startup (configurable).
- **Bcrypt password hashing** with 72-byte input limit.
- **Full pico-stack integration**: pico-ioc, pico-boot, pico-fastapi, pico-sqlalchemy.
- E2E test suite with 34 tests and >95% code coverage.
