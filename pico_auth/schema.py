"""Database schema helpers -- table creation."""

from pico_sqlalchemy import AppBase, SessionManager

import pico_auth.models  # noqa: F401 -- ensure models are registered with AppBase


async def create_tables(sm: SessionManager) -> None:
    """Create all auth tables using the SessionManager's engine."""
    async with sm.engine.begin() as conn:
        await conn.run_sync(AppBase.metadata.create_all)
