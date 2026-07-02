"""
Shared test fixtures.

The test database is a throwaway SQLite file created per session — set via
DATABASE_URL *before* any app module is imported so the engine binds to it.
"""

import os
import tempfile

# Must run before app imports.
_tmp_db = os.path.join(tempfile.mkdtemp(prefix="scanner-tests-"), "test.db")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp_db}"
os.environ["CORS_ORIGINS"] = "http://testserver"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import init_db, engine, Base
from app.main import app


@pytest_asyncio.fixture()
async def client():
    """HTTP client bound to the app with a fresh database per test."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
