# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.html).

---

## [Unreleased]

### Changed

- The test suite no longer depends on pico-boot plugin auto-discovery: it adopts pico-testing (>= 0.2.0, like the rest of the fleet) and lists `pico_sqlalchemy`, `pico_fastapi` and `pico_client_auth` explicitly. Installing pico-testing next to pico-auth used to break 83 tests, because its isolation fixture disables auto-discovery and the fixtures relied on it.

### Added

- CodeQL analysis on push, pull request and weekly, matching the rest of the fleet.

## v0.3.2 — Container image & working env configuration (2026-08-05)

### Fixed

- Environment configuration actually works. `main.py` passed an `EnvSource` alongside the YAML, but every settings class binds with `mapping="tree"` and pico-ioc keeps flat and tree sources in separate buckets, so the flat source was never consulted: `AUTH_ADMIN_PASSWORD` and friends silently did nothing. Values now arrive through `${ENV:VAR}` interpolation inside the YAML, and the README, FAQ and configuration reference describe the mechanism that exists. Requires pico-ioc >= 2.5.1, where an unset variable reports itself instead of falling back to defaults.

### Changed

- Ships as a container image. `Dockerfile` installs from the source tree instead of PyPI (the package is no longer published there, so the image was pinned to a stale release), takes the version as a build argument, and gains a healthcheck; `publish-image.yml` pushes to `ghcr.io/dperezcabrera/pico-auth` on release.
- The bundled `application.yaml` no longer enables `auto_create_admin` with the password `admin`, the exact combination the bootstrap fail-fast rejects — the image could not start as shipped.
- `LocalJWKSProvider` no longer subclasses `JWKSClient`. The container key is a lookup token, so the override needs nothing but `get_key`; the inherited HTTP fetcher and the private attributes that were mirrored to keep it quiet (`_settings`, `_endpoint`, `_fetched_at`) are gone. Requires `pico-client-auth >= 0.7.0`, which exports the key from its facade.

## v0.3.1 — PyJWT & dependency floors (2026-08-04)

### Changed

- JWT signing migrated from `python-jose` (unmaintained) to `PyJWT[crypto] >= 2.8`, aligning with pico-server-auth 0.2.0 and pico-client-auth 0.5.0. Tokens, claims and JWKS are unchanged: tokens issued before the migration keep validating.
- Dependency floors raised to the versions that carry fixes this application depends on: `pico-client-auth >= 0.6.0` (mandatory `exp`, `HS*` rejection, fail-closed revocation), `pico-sqlalchemy >= 0.5.1` (DDL no longer hangs under uvicorn) and `pico-ioc >= 2.3.3` (idempotent container shutdown).

- **Distribution: pico-auth is no longer published to PyPI.** It is a deployable application, not a library, so it is installed from a checkout (`pip install -e ".[dev]"`) or run as a container. The PyPI entry stays frozen at the previously published versions.

### Fixed

- Release builds no longer publish a `.post0` version. The generated `pico_auth/_version.py` was tracked in git, so setuptools-scm rewriting it during the build left the tree dirty and the `post-release` scheme appended `.post0` at distance zero.

---

## v0.3.0 — Post-Quantum (ML-DSA) Support, Email Credentials & Admin Management (2026-06-10)

### Added

- **EmailCredential API** — `EmailCredential` model, repository, service, and REST endpoints at `/api/v1/email-credentials`, protected by a service token (`auth.email_credentials_token`)
- **Registration toggle** — `auth.registration_enabled` setting (default `true`); when disabled, public registration returns 403 and a runtime admin endpoint exposes/controls the flag
- **Admin user management** — admin endpoints for listing and managing users
- **Docker E2E tests** — `Dockerfile.local` plus documented E2E workflow in README, getting-started, and contributing guides
- **Configurable JWT algorithm** — `auth.algorithm` setting supports `RS256` (default), `ML-DSA-65`, and `ML-DSA-87`
- **ML-DSA key generation** — Auto-generates ML-DSA key pairs (`pqc_secret.bin`, `pqc_public.bin`) via `liboqs-python`
- **ML-DSA token signing** — `JWTProvider` creates and verifies ML-DSA-signed JWTs
- **PQC JWKS** — JWKS endpoint serves `kty: "AKP"` keys with `pub` field for ML-DSA algorithms
- **`pqc` optional extra** — `pip install pico-auth[pqc]` installs `liboqs-python`
- **`auth_client.accepted_algorithms`** — Accepts RS256 + ML-DSA-65 + ML-DSA-87 by default in `application.yaml`
- PQC test suite with 18 tests using mocked oqs (no liboqs required)

### Changed

- `pico-client-auth` dependency bumped to `>=0.4.1` (PQC verification support)

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
