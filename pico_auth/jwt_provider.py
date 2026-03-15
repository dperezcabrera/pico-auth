"""JWT token creation and validation with auto-generated RSA or ML-DSA keys."""

import base64
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from jose import jwt
from pico_ioc import component

from pico_auth.config import AuthSettings

logger = logging.getLogger(__name__)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _import_oqs():
    """Lazy-import oqs, raising RuntimeError if not installed."""
    try:
        import oqs
    except ImportError as exc:
        raise RuntimeError(
            "liboqs-python is required for ML-DSA signing. Install with: pip install pico-auth[pqc]"
        ) from exc
    return oqs


@component
class JWTProvider:
    """Creates and validates JWT tokens with auto-generated RSA or ML-DSA keys."""

    def __init__(self, settings: AuthSettings):
        self._settings = settings
        self._algorithm = settings.algorithm
        self._kid = "pico-auth-1"

        if settings.is_pqc:
            self._secret_key, self._public_key_bytes = self._load_or_generate_pqc_keys()
            self._private_key = None
            self._public_key = None
        else:
            self._private_key, self._public_key = self._load_or_generate_rsa_keys()
            self._secret_key = None
            self._public_key_bytes = None

    def _load_or_generate_rsa_keys(self) -> tuple[str, str]:
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

    def _load_or_generate_pqc_keys(self) -> tuple[bytes, bytes]:
        data_dir = self._settings.data_path
        data_dir.mkdir(parents=True, exist_ok=True)
        secret_path = self._settings.pqc_key_path
        pub_path = self._settings.pqc_pub_path

        if secret_path.exists() and pub_path.exists():
            logger.info("Loaded %s keys from %s", self._algorithm, data_dir)
            return secret_path.read_bytes(), pub_path.read_bytes()

        oqs = _import_oqs()
        signer = oqs.Signature(self._algorithm)
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

        secret_path.write_bytes(secret_key)
        secret_path.chmod(0o600)
        pub_path.write_bytes(public_key)
        logger.info("Generated %s key pair at %s", self._algorithm, data_dir)
        return secret_key, public_key

    def _sign_pqc(self, signing_input: bytes) -> bytes:
        oqs = _import_oqs()
        signer = oqs.Signature(self._algorithm, self._secret_key)
        return signer.sign(signing_input)

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

        if self._settings.is_pqc:
            return self._encode_pqc_token(claims)

        return jwt.encode(
            claims,
            self._private_key,
            algorithm=self._algorithm,
            headers={"kid": self._kid},
        )

    def _encode_pqc_token(self, claims: dict) -> str:
        header = {"alg": self._algorithm, "typ": "JWT", "kid": self._kid}
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = self._sign_pqc(signing_input)
        sig_b64 = _b64url_encode(signature)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def create_refresh_token(self) -> str:
        return uuid4().hex

    def decode_access_token(self, token: str) -> dict:
        if self._settings.is_pqc:
            return self._decode_pqc_token(token)

        return jwt.decode(
            token,
            self._public_key,
            algorithms=[self._algorithm],
            audience=self._settings.audience,
            issuer=self._settings.issuer,
        )

    def _decode_pqc_token(self, token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT: expected 3 parts")

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = _b64url_decode(sig_b64)

        oqs = _import_oqs()
        verifier = oqs.Signature(self._algorithm)
        if not verifier.verify(signing_input, signature, self._public_key_bytes):
            raise ValueError("Invalid signature")

        claims = json.loads(_b64url_decode(payload_b64))
        if claims.get("exp") and time.time() > claims["exp"]:
            raise ValueError("Token has expired")
        if claims.get("iss") != self._settings.issuer:
            raise ValueError("Invalid issuer")

        token_aud = claims.get("aud")
        if isinstance(token_aud, list):
            if self._settings.audience not in token_aud:
                raise ValueError("Invalid audience")
        elif token_aud != self._settings.audience:
            raise ValueError("Invalid audience")

        return claims

    def jwks(self) -> dict:
        if self._settings.is_pqc:
            return self._jwks_pqc()
        return self._jwks_rsa()

    def _jwks_rsa(self) -> dict:
        pub_key = load_pem_public_key(self._public_key.encode())
        assert isinstance(pub_key, RSAPublicKey)
        numbers = pub_key.public_numbers()

        n_len = (numbers.n.bit_length() + 7) // 8
        e_len = max((numbers.e.bit_length() + 7) // 8, 1)

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self._kid,
                    "use": "sig",
                    "alg": self._algorithm,
                    "n": _b64url_encode(numbers.n.to_bytes(n_len, "big")),
                    "e": _b64url_encode(numbers.e.to_bytes(e_len, "big")),
                }
            ],
        }

    def _jwks_pqc(self) -> dict:
        return {
            "keys": [
                {
                    "kty": "AKP",
                    "kid": self._kid,
                    "use": "sig",
                    "alg": self._algorithm,
                    "pub": _b64url_encode(self._public_key_bytes),
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
