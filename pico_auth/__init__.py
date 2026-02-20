"""pico-auth -- minimal JWT auth server for the pico ecosystem."""

import pico_auth.local_auth_configurer as local_auth_configurer  # noqa: F401 — patches AuthFastapiConfigurer
from pico_auth.config import AuthSettings
from pico_auth.errors import AuthError
from pico_auth.jwt_provider import JWTProvider
from pico_auth.local_jwks_provider import LocalJWKSProvider
from pico_auth.models import RefreshToken, User
from pico_auth.passwords import PasswordService
from pico_auth.repository import RefreshTokenRepository, UserRepository
from pico_auth.routes import AuthController, OIDCController
from pico_auth.schema import create_tables
from pico_auth.service import AuthService

__all__ = [
    "AuthController",
    "AuthError",
    "AuthSettings",
    "AuthService",
    "JWTProvider",
    "LocalJWKSProvider",
    "OIDCController",
    "PasswordService",
    "RefreshToken",
    "RefreshTokenRepository",
    "User",
    "UserRepository",
    "create_tables",
]
