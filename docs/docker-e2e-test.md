# Docker E2E Test

This guide walks through a full end-to-end test of the pico-auth Docker image built from source.

## Prerequisites

- Docker installed and running
- `curl` and `jq` available

## 1. Build the Image from Source

```bash
docker build -t pico-auth:local .
```

## 2. Start the Container

```bash
docker run -d --name pico-auth-e2e -p 8100:8100 pico-auth:local
```

Wait a few seconds for startup, then verify the logs:

```bash
docker logs pico-auth-e2e
```

Expected output:

```
INFO:pico_auth.jwt_provider:Generated RSA key pair at /root/.pico-auth
INFO:__main__:Admin user ensured: admin@pico.local
INFO:     Started server process [1]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8100 (Press CTRL+C to quit)
```

## 3. OpenID Discovery

```bash
curl -s http://localhost:8100/.well-known/openid-configuration | jq .
```

Expected: a JSON document with `issuer`, `token_endpoint`, `jwks_uri`, and `id_token_signing_alg_values_supported: ["RS256"]`.

## 4. JWKS Endpoint

```bash
curl -s http://localhost:8100/api/v1/auth/jwks | jq .
```

Expected: a `keys` array with at least one RSA public key (`kty: "RSA"`, `alg: "RS256"`).

## 5. Register a New User

```bash
curl -s -X POST http://localhost:8100/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"secret123","display_name":"Alice"}' | jq .
```

Expected:

```json
{
  "id": "...",
  "email": "alice@example.com",
  "role": "viewer",
  "status": "active"
}
```

## 6. Login

```bash
TOKEN=$(curl -s -X POST http://localhost:8100/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"secret123"}')

echo "$TOKEN" | jq .

ACCESS_TOKEN=$(echo "$TOKEN" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN" | jq -r '.refresh_token')
```

Expected: a JSON object with `access_token`, `refresh_token`, `token_type: "Bearer"`, and `expires_in: 900`.

## 7. Get Current User Profile

```bash
curl -s http://localhost:8100/api/v1/auth/me \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
```

Expected: user profile with `email: "alice@example.com"`, `role: "viewer"`, and `status: "active"`.

## 8. Change Password

```bash
curl -s -X POST http://localhost:8100/api/v1/auth/me/password \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"old_password":"secret123","new_password":"newpass456"}' | jq .
```

## 9. Refresh Token

```bash
curl -s -X POST http://localhost:8100/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "\"$REFRESH_TOKEN\"" | jq .
```

Expected: a new token pair (same structure as login response).

## 10. Admin: Login and List Users

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8100/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@pico.local","password":"admin"}' | jq -r '.access_token')

curl -s http://localhost:8100/api/v1/auth/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

Expected: a `users` array containing both `admin@pico.local` and `alice@example.com`.

## 11. Admin: Update User Role

Get Alice's user ID from the previous response, then:

```bash
USER_ID=$(curl -s http://localhost:8100/api/v1/auth/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.users[] | select(.email=="alice@example.com") | .id')

curl -s -X PUT "http://localhost:8100/api/v1/auth/users/$USER_ID/role" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '"operator"' | jq .
```

Expected: `role: "operator"` in the response.

## 12. Cleanup

```bash
docker rm -f pico-auth-e2e
```

## Quick Smoke Test (Copy-Paste)

A minimal all-in-one script to validate the image:

```bash
#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-pico-auth:local}"
CONTAINER="pico-auth-e2e-$$"
BASE="http://localhost:8100"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> Building image..."
docker build -t pico-auth:local .

echo "==> Starting container..."
docker run -d --name "$CONTAINER" -p 8100:8100 "$IMAGE"
sleep 5

echo "==> OpenID discovery..."
curl -sf "$BASE/.well-known/openid-configuration" | jq -e '.issuer'

echo "==> JWKS..."
curl -sf "$BASE/api/v1/auth/jwks" | jq -e '.keys[0].kty'

echo "==> Register user..."
curl -sf -X POST "$BASE/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@e2e.com","password":"test1234","display_name":"E2E"}' \
  | jq -e '.email'

echo "==> Login..."
ACCESS_TOKEN=$(curl -sf -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@e2e.com","password":"test1234"}' | jq -r '.access_token')

echo "==> Get profile..."
curl -sf "$BASE/api/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq -e '.email'

echo "==> Admin login and list users..."
ADMIN_TOKEN=$(curl -sf -X POST "$BASE/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@pico.local","password":"admin"}' | jq -r '.access_token')

curl -sf "$BASE/api/v1/auth/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -e '.total >= 2'

echo ""
echo "All checks passed!"
```
