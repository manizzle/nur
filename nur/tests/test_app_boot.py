from __future__ import annotations

import os

from nur.server.app import create_app


def _paths(app) -> set[str]:
    return {route.path for route in app.router.routes}


def test_fl_routes_disabled_by_default():
    os.environ.pop("NUR_ENABLE_FL", None)
    app = create_app(db_url="sqlite+aiosqlite:///:memory:")
    assert "/fl/create-session" not in _paths(app)


def test_fl_routes_enabled_when_requested():
    os.environ["NUR_ENABLE_FL"] = "1"
    try:
        app = create_app(db_url="sqlite+aiosqlite:///:memory:")
        assert "/fl/create-session" in _paths(app)
    finally:
        os.environ.pop("NUR_ENABLE_FL", None)
