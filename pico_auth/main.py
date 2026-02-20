"""Pico Auth entrypoint -- pico-boot bootstrap."""

import asyncio
import logging

import uvicorn
from fastapi import FastAPI
from pico_boot import init
from pico_ioc import EnvSource, YamlTreeSource, configuration
from pico_sqlalchemy import SessionManager

from pico_auth.config import AuthSettings
from pico_auth.schema import create_tables
from pico_auth.service import AuthService

logger = logging.getLogger(__name__)


def create_container(config_path: str = "application.yaml"):
    """Bootstrap the pico-ioc container with all auth components."""
    config = configuration(
        YamlTreeSource(config_path),
        EnvSource(),
    )
    return init(modules=["pico_auth"], config=config)


async def main() -> None:
    container = create_container()
    app = container.get(FastAPI)

    # Create database tables
    sm = container.get(SessionManager)
    await create_tables(sm)

    # Auto-create admin user if configured
    settings = container.get(AuthSettings)
    if settings.auto_create_admin:
        service = container.get(AuthService)
        await service.ensure_admin(settings.admin_email, settings.admin_password)
        logger.info("Admin user ensured: %s", settings.admin_email)

    config = uvicorn.Config(app, host="0.0.0.0", port=8100)
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
