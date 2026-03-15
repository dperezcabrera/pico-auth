"""Auth server configuration using pico-ioc @configured."""

from dataclasses import dataclass, field
from pathlib import Path

from pico_ioc import configured

_PQC_ALGORITHMS = ("ML-DSA-65", "ML-DSA-87")


@configured(target="self", prefix="auth", mapping="tree")
@dataclass
class AuthSettings:
    """Auth server settings from application.yaml / env vars."""

    data_dir: str = "~/.pico-auth"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    issuer: str = "http://localhost:8100"
    audience: str = "pico-bot"
    algorithm: str = "RS256"
    auto_create_admin: bool = True
    admin_email: str = "admin@pico.local"
    admin_password: str = "admin"
    registration_enabled: bool = True
    email_credentials_token: str = ""

    @property
    def is_pqc(self) -> bool:
        return self.algorithm in _PQC_ALGORITHMS

    @property
    def data_path(self) -> Path:
        return Path(self.data_dir).expanduser()

    @property
    def private_key_path(self) -> Path:
        return self.data_path / "private.pem"

    @property
    def public_key_path(self) -> Path:
        return self.data_path / "public.pem"

    @property
    def pqc_key_path(self) -> Path:
        return self.data_path / "pqc_secret.bin"

    @property
    def pqc_pub_path(self) -> Path:
        return self.data_path / "pqc_public.bin"
