Read and follow ./AGENTS.md for project conventions.

## Pico Ecosystem Context

pico-auth is an application (not a library) that provides JWT authentication using the full pico stack. It uses `pico_boot.init()` to bootstrap all components from `pico_auth` module.

## Key Reminders

- This is an APPLICATION, not a library -- do not publish to PyPI
- Flat package layout: `pico_auth/` (not `src/pico_auth/`)
- requires-python >= 3.11
- Commit messages: one line only
- Routes prefix: `/api/v1/auth` -- do not change the API versioning
- JWT algorithm: RS256 only -- do not switch to HS256
- Refresh tokens must be hashed (SHA-256) before storage -- never store raw tokens
- Password hashing uses bcrypt directly (not passlib)
- Auth/authz errors: HTTP 401/403 with `{"detail": "..."}` (via pico-client-auth middleware)
- Business logic errors: HTTP 200 with `{"error": "..."}` (e.g. duplicate email, wrong password, invalid role)
