"""
Shared test fixtures.

The test database is a throwaway SQLite file created per session — set via
DATABASE_URL *before* any app module is imported so the engine binds to it.
"""

import os
import tempfile

# Must run before app imports.
# TEST_DATABASE_URL runs the suite against another engine (e.g. Postgres);
# by default each session gets a throwaway SQLite file.
# Every test drops and recreates all tables, so refuse any database whose
# name doesn't say it is disposable — a mistyped URL must not wipe real data.
_tmp_db = os.path.join(tempfile.mkdtemp(prefix="scanner-tests-"), "test.db")
_test_url = os.environ.get("TEST_DATABASE_URL")
if _test_url and "test" not in _test_url.rsplit("/", 1)[-1].split("?")[0].lower():
    raise SystemExit(
        "TEST_DATABASE_URL must name a disposable database containing 'test' "
        "(e.g. .../cipherwatch_test); the suite drops every table in it."
    )
os.environ["DATABASE_URL"] = _test_url or f"sqlite+aiosqlite:///{_tmp_db}"
os.environ["CORS_ORIGINS"] = "http://testserver"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.database import init_db, engine, Base
from app.main import app


@pytest_asyncio.fixture()
async def client():
    """HTTP client bound to the app with a fresh database and limits per test."""
    from app.security import scan_limiter

    scan_limiter.reset()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
    # Each test runs on its own event loop; pooled connections (asyncpg) are
    # bound to the loop that opened them, so drop them between tests.
    await engine.dispose()
