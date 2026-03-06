# Getting Started

## Prerequisites

- Python 3.11+
- pip

## Installation

```bash
git clone https://github.com/dperezcabrera/pico-auth.git
cd pico-auth
pip install -e ".[dev]"
```

## Running the Server

```bash
python -m pico_auth.main
```

The server starts on `http://localhost:8100` with:

- SQLite database at `auth.db`
- RSA keys generated at `~/.pico-auth/`
- Admin user: `admin@pico.local` / `admin`

## Your First Request

### Register a User

```bash
curl -X POST http://localhost:8100/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123", "display_name": "Alice"}'
```

### Login

```bash
curl -X POST http://localhost:8100/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "password": "secret123"}'
```

### Use the Token

```bash
TOKEN="<access_token from login response>"
curl http://localhost:8100/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

## Running Tests

```bash
# Unit and integration tests
pytest tests/ -v

# Docker E2E tests (requires Docker and ../pico-client-auth)
pytest tests/test_docker_e2e.py -m docker -v
```

Docker E2E tests are excluded from the default test suite. They build a local Docker image, start a container, and run HTTP tests against it.

## Next Steps

- [Configuration](./configuration.md) - Customize settings
- [API Endpoints](./api-endpoints.md) - Full API reference
- [Authentication Flow](./auth-flow.md) - Understand JWT lifecycle
- [Docker E2E Test](./docker-e2e-test.md) - Full Docker testing guide
