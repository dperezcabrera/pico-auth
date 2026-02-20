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
pytest tests/ -v
```

## Next Steps

- [Configuration](./configuration.md) - Customize settings
- [API Endpoints](./api-endpoints.md) - Full API reference
- [Authentication Flow](./auth-flow.md) - Understand JWT lifecycle
