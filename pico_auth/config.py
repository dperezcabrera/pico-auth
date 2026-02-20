"""Auth server configuration using pico-ioc @configured."""

from dataclasses import dataclass
from pathlib import Path

from pico_ioc import configured


@configured(target="self", prefix="auth", mapping="tree")
@dataclass
class AuthSettings:
    """Auth server settings from application.yaml / env vars."""

    data_dir: str = "~/.pico-auth"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    issuer: str = "http://localhost:8100"
    audience: str = "pico-bot"
    auto_create_admin: bool = True
    admin_email: str = "admin@pico.local"
    admin_password: str = "admin"

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir).expanduser()

    @property
    def private_key_path(self) -> Path:
        return self.data_path / "private.pem"

    @property
    def public_key_path(self) -> Path:
        return self.data_path / "public.pem"
