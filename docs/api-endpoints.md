# API Endpoints

All auth endpoints are prefixed with `/api/v1/auth`.

## Public Endpoints

### POST /api/v1/auth/register

Register a new user account.

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "secret123",
  "display_name": "Alice"
}
```

**Response:**
```json
{
  "id": "a1b2c3d4e5f6",
  "email": "alice@example.com",
  "role": "viewer",
  "status": "active"
}
```

### POST /api/v1/auth/login

Authenticate and receive tokens.

**Request:**
```json
{
  "email": "alice@example.com",
  "password": "secret123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### POST /api/v1/auth/refresh

Exchange a refresh token for new token pair (rotation).

**Request:**
```json
"a1b2c3d4e5f6..."
```

**Response:** Same as login.

### GET /api/v1/auth/jwks

JSON Web Key Set for token verification.

**Response:**
```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "pico-auth-1",
    "use": "sig",
    "alg": "RS256",
    "n": "...",
    "e": "AQAB"
  }]
}
```

### GET /.well-known/openid-configuration

OIDC discovery document.

## Authenticated Endpoints

All require `Authorization: Bearer <access_token>` header.

### GET /api/v1/auth/me

Get current user profile.

**Response:**
```json
{
  "id": "a1b2c3d4e5f6",
  "email": "alice@example.com",
  "display_name": "Alice",
  "role": "viewer",
  "org_id": "default",
  "status": "active",
  "created_at": "2025-01-01T00:00:00+00:00",
  "last_login_at": "2025-01-02T12:00:00+00:00"
}
```

### POST /api/v1/auth/me/password

Change the current user's password. Invalidates all refresh tokens.

**Request:**
```json
{
  "old_password": "old",
  "new_password": "new"
}
```

## Admin Endpoints

Require `superadmin` or `org_admin` role.

### GET /api/v1/auth/users

List all users.

**Response:**
```json
{
  "users": [
    {"id": "...", "email": "...", "display_name": "...", "role": "...", "org_id": "...", "status": "..."}
  ],
  "total": 1
}
```

### PUT /api/v1/auth/users/{user_id}/role

Update a user's role. Valid roles: `superadmin`, `org_admin`, `operator`, `viewer`.

**Request:**
```json
"operator"
```

**Response:**
```json
{
  "id": "...",
  "email": "...",
  "role": "operator"
}
```

## Group Endpoints

All group endpoints are prefixed with `/api/v1/groups`.

### POST /api/v1/groups

Create a new group. Requires `superadmin` or `org_admin` role.

**Request:**
```json
{
  "name": "engineering",
  "description": "Engineering team"
}
```

**Response:**
```json
{
  "id": "g1a2b3c4d5e6",
  "name": "engineering",
  "org_id": "default"
}
```

### GET /api/v1/groups

List groups for the current user's organization.

**Response:**
```json
{
  "groups": [
    {"id": "g1...", "name": "engineering", "description": "Engineering team", "org_id": "default"}
  ],
  "total": 1
}
```

### GET /api/v1/groups/{group_id}

Get group details with member list.

**Response:**
```json
{
  "id": "g1...",
  "name": "engineering",
  "description": "Engineering team",
  "org_id": "default",
  "members": [
    {"user_id": "u1...", "joined_at": "2026-02-21T00:00:00+00:00"}
  ]
}
```

### PUT /api/v1/groups/{group_id}

Update group name and/or description. Requires `superadmin` or `org_admin` role.

**Request:**
```json
{
  "name": "platform",
  "description": "Platform engineering"
}
```

### DELETE /api/v1/groups/{group_id}

Delete a group and all its memberships. Requires `superadmin` or `org_admin` role.

### POST /api/v1/groups/{group_id}/members

Add a user to a group. Requires `superadmin` or `org_admin` role.

**Request:**
```json
"user-id-here"
```

### DELETE /api/v1/groups/{group_id}/members/{user_id}

Remove a user from a group. Requires `superadmin` or `org_admin` role.

---

## Error Responses

All errors return HTTP 200 with an error field:

```json
{
  "error": "Invalid email or password"
}
```
