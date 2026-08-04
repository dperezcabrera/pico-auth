# Configuration

Pico-Auth loads configuration from `application.yaml` using pico-ioc's `YamlTreeSource`, with environment variable overrides via `EnvSource`.

## application.yaml

```yaml
auth:
  data_dir: "~/.pico-auth"              # Key storage directory
  access_token_expire_minutes: 15        # JWT access token lifetime
  refresh_token_expire_days: 7           # Refresh token lifetime
  issuer: "http://localhost:8100"        # JWT issuer claim (iss)
  audience: "pico-bot"                   # JWT audience claim (aud)
  algorithm: "RS256"                     # Signing algorithm: RS256, ML-DSA-65, or ML-DSA-87
  auto_create_admin: true                # Create admin user on startup
  admin_email: "admin@pico.local"        # Default admin email
  admin_password: "admin"                # Default admin password

database:
  url: "sqlite+aiosqlite:///auth.db"     # SQLAlchemy async URL
  echo: false                            # Log SQL queries

auth_client:
  enabled: true                          # Enable auth middleware
  issuer: "http://localhost:8100"        # Must match auth.issuer
  audience: "pico-bot"                   # Must match auth.audience
  accepted_algorithms:                   # Algorithms accepted for verification
    - "RS256"
    - "ML-DSA-65"
    - "ML-DSA-87"

fastapi:
  title: "Pico Auth API"
  version: "0.2.0"
```

## Environment Variable Overrides

Settings are bound from the configuration tree, so environment values enter through `${ENV:VAR}` interpolation **inside the YAML** — there is no implicit `AUTH_ISSUER`-style override. Reference the variables you want to inject:

```yaml
auth:
  issuer: "${ENV:AUTH_ISSUER}"
  admin_password: "${ENV:AUTH_ADMIN_PASSWORD}"

database:
  url: "${ENV:DATABASE_URL}"
```

### Example

```bash
AUTH_ISSUER=https://auth.prod.myapp.com \
AUTH_ADMIN_PASSWORD=strong-random-password \
DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/auth \
python -m pico_auth.main
```

A referenced variable that is not set stops startup with `Missing ENV var AUTH_ADMIN_PASSWORD` (pico-ioc >= 2.5.1); earlier versions silently fell back to the field default.

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
    algorithm: str = "RS256"          # RS256, ML-DSA-65, or ML-DSA-87
    auto_create_admin: bool = True
    admin_email: str = "admin@pico.local"
    admin_password: str = "admin"
```

The `algorithm` field determines which signing algorithm `JWTProvider` uses:

| Algorithm | Key Type | Key Files | Requires |
|-----------|----------|-----------|----------|
| `RS256` | RSA 2048-bit | `private.pem`, `public.pem` | PyJWT |
| `ML-DSA-65` | ML-DSA (NIST Level 3) | `pqc_secret.bin`, `pqc_public.bin` | liboqs-python (`pqc` extra) |
| `ML-DSA-87` | ML-DSA (NIST Level 5) | `pqc_secret.bin`, `pqc_public.bin` | liboqs-python (`pqc` extra) |

## Production Recommendations

- Point `auth.admin_password` at `${ENV:AUTH_ADMIN_PASSWORD}` and give it a strong random value
- Set `auth.issuer` to your public URL
- Use PostgreSQL instead of SQLite for `database.url`
- Set `auth.auto_create_admin: false` after first deployment
- Store keys on a persistent volume (`auth.data_dir`)
- For post-quantum readiness, set `auth.algorithm: ML-DSA-65` and install the `pqc` extra
