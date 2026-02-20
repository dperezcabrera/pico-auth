"""Shared fixtures for pico-auth tests."""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pico_boot import init
from pico_ioc import DictSource, configuration
from pico_sqlalchemy import SessionManager

from pico_auth.schema import create_tables


@pytest.fixture
def container(tmp_path):
    """Build a fully-wired pico-ioc container."""
    db_path = tmp_path / "test.db"
    auth_data = tmp_path / "auth-keys"
    config = configuration(
        DictSource(
            {
                "auth": {
                    "data_dir": str(auth_data),
                    "access_token_expire_minutes": 15,
                    "refresh_token_expire_days": 7,
                    "issuer": "http://test",
                    "audience": "pico-bot",
                    "auto_create_admin": False,
                    "admin_email": "admin@test.local",
                    "admin_password": "admin",
                },
                "database": {
                    "url": f"sqlite+aiosqlite:///{db_path}",
                    "echo": False,
                },
                "fastapi": {"title": "Test Auth", "version": "0.1.0"},
                "auth_client": {"enabled": True, "issuer": "http://test", "audience": "pico-bot"},
            }
        )
    )
    return init(modules=["pico_auth"], config=config)


@pytest_asyncio.fixture
async def app(container):
    """FastAPI app with tables created."""
    sm = container.get(SessionManager)
    await create_tables(sm)
    return container.get(FastAPI)


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
