"""Local JWKS provider that reads keys directly from JWTProvider."""

from pico_client_auth.config import AuthClientSettings
from pico_client_auth.jwks_client import JWKSClient
from pico_ioc import component

from pico_auth.jwt_provider import JWTProvider


@component(name=JWKSClient, primary=True)
class LocalJWKSProvider(JWKSClient):
    """JWKS provider that avoids HTTP by reading keys from the local JWTProvider.

    Registered with ``name=JWKSClient`` so that pico-ioc replaces the default
    ``JWKSClient`` (which fetches keys over HTTP) when resolving that type.
    """

    def __init__(self, settings: AuthClientSettings, jwt_provider: JWTProvider):
        self._settings = settings
        self._endpoint = ""
        self._fetched_at = 0.0
        jwks = jwt_provider.jwks()
        self._keys = {k["kid"]: k for k in jwks.get("keys", [])}

    async def get_key(self, kid: str) -> dict:
        if kid in self._keys:
            return self._keys[kid]
        raise KeyError(f"Key ID '{kid}' not found in local JWKS")
