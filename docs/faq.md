# FAQ

## Why RS256 instead of HS256?

RS256 (asymmetric) allows other services to verify tokens using the public key without knowing the signing secret. The JWKS endpoint exposes the public key for service-to-service validation.

## Where are the RSA keys stored?

By default in `~/.pico-auth/`. The directory is created automatically on first run. The private key file has `0600` permissions. Configure with `AUTH_DATA_DIR`.

## Can I use PostgreSQL instead of SQLite?

Yes. Set the `DATABASE_URL` environment variable:

```bash
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/auth python -m pico_auth.main
```

## Why do errors return HTTP 200?

Pico-Auth returns errors in the JSON body (`{"error": "message"}`) rather than using HTTP status codes. This simplifies client-side handling and is consistent across all endpoints.

## How does refresh token rotation work?

Each refresh token can only be used once. When you call `/refresh`, the old token is deleted and a new one is issued. If someone steals a token and uses it first, your next refresh will fail -- this signals a potential compromise.

## How do I create the first admin user?

By default, `auto_create_admin: true` creates an admin user on startup. Set `AUTH_ADMIN_EMAIL` and `AUTH_ADMIN_PASSWORD` environment variables for production.

## What roles are available?

Four built-in roles: `superadmin`, `org_admin`, `operator`, `viewer`. Only `superadmin` and `org_admin` can access admin endpoints (list users, update roles).
