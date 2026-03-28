"""Tests for the /contribute/quick zero-typing eval form."""
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def _make_app():
    """Create a fresh app with initialized database."""
    import nur.server.app as app_mod
    from nur.server.app import create_app
    from nur.server.db import Database

    app = create_app(db_url="sqlite+aiosqlite:///:memory:")
    db = Database("sqlite+aiosqlite:///:memory:")
    await db.init()
    app_mod._db = db
    return app


@pytest.mark.asyncio
async def test_quick_contribute_form():
    app = await _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/contribute/quick")
        assert resp.status_code == 200
        assert "What do you use" in resp.text
        assert "Score it" in resp.text
        assert "Would you buy it again" in resp.text
