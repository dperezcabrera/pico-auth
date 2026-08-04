"""Local JWKS provider that reads keys directly from JWTProvider."""

from pico_client_auth import JWKSClient
from pico_ioc import component

from pico_auth.jwt_provider import JWTProvider


@component(name=JWKSClient, primary=True)
class LocalJWKSProvider:
    """Serves this server's own keys, so validation never calls its own endpoint.

    ``JWKSClient`` is the container key, not a base class: providing
    ``get_key`` is the whole contract.
    """

    def __init__(self, jwt_provider: JWTProvider):
        self._keys = {k["kid"]: k for k in jwt_provider.jwks().get("keys", [])}

    async def get_key(self, kid: str) -> dict:
        if kid not in self._keys:
            raise KeyError(f"Key ID '{kid}' not found in local JWKS")
        return self._keys[kid]
