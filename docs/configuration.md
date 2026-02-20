# Configuration

Pico-Auth loads configuration from `application.yaml` using pico-ioc's `YamlTreeSource`, with environment variable overrides via `EnvSource`.

## application.yaml

```yaml
auth:
  data_dir: "~/.pico-auth"              # RSA key storage directory
  access_token_expire_minutes: 15        # JWT access token lifetime
  refresh_token_expire_days: 7           # Refresh token lifetime
  issuer: "http://localhost:8100"        # JWT issuer claim (iss)
  audience: "pico-bot"                   # JWT audience claim (aud)
  auto_create_admin: true                # Create admin user on startup
  admin_email: "admin@pico.local"        # Default admin email
  admin_password: "admin"                # Default admin password

database:
  url: "sqlite+aiosqlite:///auth.db"     # SQLAlchemy async URL
  echo: false                            # Log SQL queries

fastapi:
  title: "Pico Auth API"
  version: "0.1.0"
```

## Environment Variable Overrides

Every setting can be overridden with environment variables using uppercase and underscores:

| Setting | Environment Variable |
|---------|---------------------|
| `auth.issuer` | `AUTH_ISSUER` |
| `auth.admin_password` | `AUTH_ADMIN_PASSWORD` |
| `auth.access_token_expire_minutes` | `AUTH_ACCESS_TOKEN_EXPIRE_MINUTES` |
| `database.url` | `DATABASE_URL` |

### Example

```bash
AUTH_ISSUER=https://auth.prod.myapp.com \
AUTH_ADMIN_PASSWORD=strong-random-password \
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/auth \
python -m pico_auth.main
```

## AuthSettings Dataclass

The `AuthSettings` class is wired via pico-ioc's `@configured` decorator:

```python
@configured(target="self", prefix="auth", mapping="tree")
@dataclass
class AuthSettings:
    data_dir: str = "~/.pico-auth"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    issuer: str = "http://localhost:8100"
    audience: str = "pico-bot"
    auto_create_admin: bool = True
    admin_email: str = "admin@pico.local"
    admin_password: str = "admin"
```

## Production Recommendations

- Set `AUTH_ADMIN_PASSWORD` to a strong random value
- Set `AUTH_ISSUER` to your public URL
- Use PostgreSQL instead of SQLite for `DATABASE_URL`
- Set `AUTH_AUTO_CREATE_ADMIN=false` after first deployment
- Store RSA keys on a persistent volume (`AUTH_DATA_DIR`)
