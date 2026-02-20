"""Compatibility patches for pico-client-auth + pico-fastapi integration.

1. **DatabaseConfigurer guard**: Both ``FastApiConfigurer`` and
   ``DatabaseConfigurer`` are structurally identical ``@runtime_checkable``
   protocols.  ``AuthFastapiConfigurer`` therefore gets matched as a
   ``DatabaseConfigurer`` by pico-sqlalchemy, which calls
   ``configure(engine)``.  We patch ``configure`` to skip non-FastAPI calls.

2. **Decorator attribute forwarding**: pico-fastapi wraps controller methods
   into new handler functions.  The ``@allow_anonymous`` /
   ``@requires_role`` attributes set by pico-client-auth are lost.  We patch
   ``_register_route`` to copy them onto the generated handler.
"""

from fastapi import FastAPI
from pico_client_auth.configurer import AuthFastapiConfigurer
from pico_client_auth.decorators import PICO_ALLOW_ANONYMOUS, PICO_REQUIRED_ROLES
from pico_fastapi import factory as _fastapi_factory

# ---------------------------------------------------------------------------
# Patch 1: guard AuthFastapiConfigurer.configure against non-FastAPI calls
# ---------------------------------------------------------------------------

_original_configure = AuthFastapiConfigurer.configure


def _safe_configure(self, app):
    if not isinstance(app, FastAPI):
        return
    _original_configure(self, app)


AuthFastapiConfigurer.configure = _safe_configure

# ---------------------------------------------------------------------------
# Patch 2: copy pico-client-auth decorator attributes to route handlers
# ---------------------------------------------------------------------------

_original_register_route = _fastapi_factory._register_route


def _register_route_with_attrs(router, container, cls, name, method, route_info):
    _original_register_route(router, container, cls, name, method, route_info)
    # The handler was just added as the last route — copy decorator attrs
    if router.routes:
        last_route = router.routes[-1]
        endpoint = getattr(last_route, "endpoint", None)
        if endpoint is not None:
            for attr in (PICO_ALLOW_ANONYMOUS, PICO_REQUIRED_ROLES):
                val = getattr(method, attr, None)
                if val is not None:
                    setattr(endpoint, attr, val)


_fastapi_factory._register_route = _register_route_with_attrs
