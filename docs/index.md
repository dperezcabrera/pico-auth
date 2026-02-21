# Pico-Auth Documentation

Welcome to the official documentation for **Pico-Auth**, a minimal JWT authentication server for the Pico ecosystem.

## What is Pico-Auth?

Pico-Auth is a ready-to-run authentication server built on the [pico-framework](https://github.com/dperezcabrera/pico-ioc) stack. It provides:

- **RS256 JWT tokens** with auto-generated RSA key pairs
- **Refresh token rotation** with SHA-256 hashed storage
- **Role-based access control** (superadmin, org_admin, operator, viewer)
- **Group management** with CRUD API, membership, and `groups` JWT claim
- **OIDC discovery** endpoints for service-to-service integration
- **Zero-config startup** with SQLite and auto-created admin

## Quick Links

| Document | Description |
|----------|-------------|
| [Getting Started](getting-started.md) | Run pico-auth in 2 minutes |
| [Configuration](configuration.md) | application.yaml settings |
| [API Endpoints](api-endpoints.md) | Complete REST API reference |
| [Authentication Flow](auth-flow.md) | JWT lifecycle and refresh rotation |
| [Architecture](architecture.md) | Internal design and component wiring |
| [API Reference](api-reference.md) | Python API documentation |
| [Ecosystem](ecosystem.md) | Pico framework packages |
| [FAQ](faq.md) | Frequently asked questions |

## Installation

```bash
pip install -e ".[dev]"
python -m pico_auth.main
```

The server starts on `http://localhost:8100` with an auto-created admin user.
