"""Shared fixtures for pico-auth tests."""

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pico_sqlalchemy import SessionManager

from pico_auth.schema import create_tables


@pytest.fixture
def pico_stack(make_container):
    """make_container with this app's plugin stack always wired in.

    The plugins are listed rather than auto-discovered: the suite must wire
    the same stack whatever else happens to be installed in the venv.
    """
    return lambda config: make_container(
        "pico_sqlalchemy", "pico_fastapi", "pico_client_auth", config=config
    )


@pytest.fixture
def container(pico_stack, tmp_path):
    """Build a fully-wired pico-ioc container."""
    db_path = tmp_path / "test.db"
    auth_data = tmp_path / "auth-keys"
    return pico_stack(
        {
            "auth": {
                "data_dir": str(auth_data),
                "access_token_expire_minutes": 15,
                "refresh_token_expire_days": 7,
                "issuer": "http://test",
                "audience": "pico-bot",
                "algorithm": "RS256",
                "auto_create_admin": False,
                "admin_email": "admin@test.local",
                "admin_password": "admin",
                "registration_enabled": True,
                "email_credentials_token": "test-token",
            },
            "database": {
                "url": f"sqlite+aiosqlite:///{db_path}",
                "echo": False,
            },
            "fastapi": {"title": "Test Auth", "version": "0.1.0"},
            "auth_client": {"enabled": True, "issuer": "http://test", "audience": "pico-bot"},
        }
    )


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
