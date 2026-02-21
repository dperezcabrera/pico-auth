"""Compatibility patches for pico-client-auth + pico-fastapi integration.

**Decorator attribute forwarding**: pico-fastapi wraps controller methods
   into new handler functions.  The ``@allow_anonymous`` /
   ``@requires_role`` attributes set by pico-client-auth are lost.  We patch
   ``_register_route`` to copy them onto the generated handler.
"""

from pico_client_auth.decorators import (
    PICO_ALLOW_ANONYMOUS,
    PICO_REQUIRED_GROUPS,
    PICO_REQUIRED_ROLES,
)
from pico_fastapi import factory as _fastapi_factory

# ---------------------------------------------------------------------------
# Patch: copy pico-client-auth decorator attributes to route handlers
# ---------------------------------------------------------------------------

_original_register_route = _fastapi_factory._register_route


def _register_route_with_attrs(router, container, cls, name, method, route_info):
    _original_register_route(router, container, cls, name, method, route_info)
    # The handler was just added as the last route — copy decorator attrs
    if router.routes:
        last_route = router.routes[-1]
        endpoint = getattr(last_route, "endpoint", None)
        if endpoint is not None:
            for attr in (PICO_ALLOW_ANONYMOUS, PICO_REQUIRED_ROLES, PICO_REQUIRED_GROUPS):
                val = getattr(method, attr, None)
                if val is not None:
                    setattr(endpoint, attr, val)


_fastapi_factory._register_route = _register_route_with_attrs
