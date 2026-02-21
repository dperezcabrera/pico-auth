"""JWT token creation and validation with auto-generated RSA keys."""

import base64
import logging
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jose import jwt
from pico_ioc import component

from pico_auth.config import AuthSettings

logger = logging.getLogger(__name__)


@component
class JWTProvider:
    """Creates and validates RS256 JWT tokens with auto-generated RSA keys."""

    def __init__(self, settings: AuthSettings):
        self._settings = settings
        self._algorithm = "RS256"
        self._kid = "pico-auth-1"
        self._private_key, self._public_key = self._load_or_generate_keys()

    def _load_or_generate_keys(self) -> tuple[str, str]:
        data_dir = self._settings.data_path
        data_dir.mkdir(parents=True, exist_ok=True)
        priv_path = self._settings.private_key_path
        pub_path = self._settings.public_key_path

        if priv_path.exists() and pub_path.exists():
            logger.info("Loaded RSA keys from %s", data_dir)
            return priv_path.read_text(), pub_path.read_text()

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        public_pem = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

        priv_path.write_text(private_pem)
        priv_path.chmod(0o600)
        pub_path.write_text(public_pem)
        logger.info("Generated RSA key pair at %s", data_dir)
        return private_pem, public_pem

    def create_access_token(
        self,
        user_id: str,
        email: str,
        role: str,
        org_id: str,
        groups: list[str] | None = None,
    ) -> str:
        now = datetime.now(UTC)
        exp = now + timedelta(minutes=self._settings.access_token_expire_minutes)
        claims = {
            "sub": user_id,
            "email": email,
            "role": role,
            "org_id": org_id,
            "groups": groups or [],
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": uuid4().hex[:12],
        }
        return jwt.encode(
            claims,
            self._private_key,
            algorithm=self._algorithm,
            headers={"kid": self._kid},
        )

    def create_refresh_token(self) -> str:
        return uuid4().hex

    def decode_access_token(self, token: str) -> dict:
        return jwt.decode(
            token,
            self._public_key,
            algorithms=[self._algorithm],
            audience=self._settings.audience,
            issuer=self._settings.issuer,
        )

    def jwks(self) -> dict:
        pub_key = load_pem_public_key(self._public_key.encode())
        numbers = pub_key.public_numbers()

        def _b64url(num: int, length: int) -> str:
            return (
                base64.urlsafe_b64encode(
                    num.to_bytes(length, "big"),
                )
                .rstrip(b"=")
                .decode()
            )

        n_len = (numbers.n.bit_length() + 7) // 8
        e_len = max((numbers.e.bit_length() + 7) // 8, 1)

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self._kid,
                    "use": "sig",
                    "alg": self._algorithm,
                    "n": _b64url(numbers.n, n_len),
                    "e": _b64url(numbers.e, e_len),
                }
            ],
        }

    def openid_configuration(self) -> dict:
        iss = self._settings.issuer
        return {
            "issuer": iss,
            "token_endpoint": f"{iss}/api/v1/auth/login",
            "jwks_uri": f"{iss}/api/v1/auth/jwks",
            "response_types_supported": ["token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [self._algorithm],
        }
