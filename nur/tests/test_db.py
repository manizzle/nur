from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest
from sqlalchemy import text

from nur.server.db import Database


@pytest.mark.asyncio
async def test_init_upgrades_populated_older_schema_with_defaults():
    """Startup migrations should not fail when a populated DB is missing newer columns."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        conn.execute(
            """
            CREATE TABLE api_keys (
                id VARCHAR(36) PRIMARY KEY,
                email VARCHAR(200) NOT NULL,
                api_key VARCHAR(64) NOT NULL,
                org_name VARCHAR(200),
                public_key VARCHAR(64),
                tier VARCHAR(20),
                created_at DATETIME NOT NULL,
                last_used DATETIME,
                request_count INTEGER
            )
            """
        )
        conn.execute(
            """
            INSERT INTO api_keys (id, email, api_key, created_at, request_count)
            VALUES ('1', 'ops@example.com', 'secret', '2024-01-01 00:00:00', 7)
            """
        )
        conn.commit()
        conn.close()

        db = Database(f"sqlite+aiosqlite:///{path}")
        await db.init()

        async with db.session() as session:
            result = await session.execute(
                text(
                    "SELECT invite_count, tier, request_count "
                    "FROM api_keys WHERE id = '1'"
                )
            )
            row = result.one()

        assert row.invite_count == 0
        assert row.tier is None
        assert row.request_count == 7
    finally:
        if "db" in locals():
            await db.close()
        os.unlink(path)
