"""
FastAPI application — the nur server.

Endpoints:
  POST /contribute/submit       — receive EvalRecord
  POST /contribute/attack-map   — receive AttackMap
  POST /contribute/ioc-bundle   — receive IOCBundle
  POST /analyze                 — contribute AND get actionable intelligence
  GET  /health                  — liveness check
  GET  /stats                   — contribution counts (anonymized)
  GET  /query/*                 — aggregated read-side queries
  POST /secagg/*                — secure aggregation coordinator
  GET  /intelligence/*          — market maps, threat mapping, danger radar
  GET  /search/*                — enhanced vendor/category search, comparisons
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .db import Database
from .routes.query import router as query_router
from .routes.secagg import router as secagg_router
from .routes.intelligence import router as intel_router
from .routes.search import router as search_router


# ── App setup ────────────────────────────────────────────────────────────────

_db: Database | None = None


def get_db() -> Database:
    if _db is None:
        raise RuntimeError("Database not initialized")
    return _db


async def _feed_ingest_loop(app: FastAPI):
    """Background task: scrape public feeds every hour (if NUR_AUTO_INGEST=1)."""
    port = getattr(app.state, "port", 8000)
    while True:
        try:
            from ..feeds import scrape_all, bundle_iocs, ingest_to_server

            results = scrape_all()
            total = 0
            for feed_name, iocs in results.items():
                if not iocs:
                    continue
                bundles = bundle_iocs(iocs, feed_name)
                count = ingest_to_server(f"http://127.0.0.1:{port}", bundles)
                total += count
            if total > 0:
                print(f"  [feed-ingest] Ingested {total} bundles from public feeds")
        except Exception as e:
            print(f"  [feed-ingest] Error: {e}")
        await asyncio.sleep(3600)  # every hour


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db
    db_url = app.state.db_url if hasattr(app.state, "db_url") else "sqlite+aiosqlite:///nur.db"
    _db = Database(db_url)
    await _db.init()

    # Start auto-ingest background task if enabled
    ingest_task = None
    if os.environ.get("NUR_AUTO_INGEST") == "1":
        ingest_task = asyncio.create_task(_feed_ingest_loop(app))
        print("  [feed-ingest] Auto-ingest enabled (every 60 min)")

    yield

    if ingest_task is not None:
        ingest_task.cancel()
        try:
            await ingest_task
        except asyncio.CancelledError:
            pass

    await _db.close()
    _db = None


def create_app(db_url: str = "sqlite+aiosqlite:///nur.db") -> FastAPI:
    app = FastAPI(
        title="nur",
        description="Privacy-preserving federated threat intelligence server",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.db_url = db_url

    # ── API key auth middleware ──────────────────────────────────────────
    api_key = os.environ.get("NUR_API_KEY")

    @app.middleware("http")
    async def api_key_auth(request: Request, call_next):
        if api_key and (request.url.path.startswith("/contribute/") or request.url.path == "/analyze") and request.method == "POST":
            provided = request.headers.get("X-API-Key")
            if provided != api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"},
                )
        return await call_next(request)

    app.include_router(query_router)
    app.include_router(secagg_router)
    app.include_router(intel_router)
    app.include_router(search_router)

    # Conditionally include FL router
    try:
        from ..fl.server import router as fl_router
        app.include_router(fl_router)
    except ImportError:
        pass  # FL module not available (missing numpy)

    # ── Root ──────────────────────────────────────────────────────────

    from fastapi.responses import HTMLResponse

    @app.get("/", response_class=HTMLResponse)
    async def root():
        db = get_db()
        stats = await db.get_stats()
        total = stats.get("total_contributions", 0)
        vendors = stats.get("unique_vendors", 0)
        by_type = stats.get("by_type", {})
        iocs = by_type.get("ioc_bundle", 0)
        attacks = by_type.get("attack_map", 0)
        evals = by_type.get("eval", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nur</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #0a0a0a;
    color: #c0c0c0;
    font-family: 'Courier New', monospace;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }}
  .container {{
    max-width: 640px;
    padding: 40px 24px;
    text-align: center;
  }}
  h1 {{
    font-size: 4em;
    color: #f0f0f0;
    letter-spacing: 0.3em;
    margin-bottom: 8px;
    text-shadow: 0 0 40px rgba(255,255,255,0.1);
  }}
  .arabic {{
    font-size: 1.4em;
    color: #666;
    margin-bottom: 32px;
    direction: rtl;
  }}
  .tagline {{
    font-size: 1.1em;
    color: #888;
    margin-bottom: 48px;
    line-height: 1.6;
  }}
  .stats {{
    display: flex;
    justify-content: center;
    gap: 32px;
    margin-bottom: 48px;
    flex-wrap: wrap;
  }}
  .stat {{
    text-align: center;
  }}
  .stat-num {{
    font-size: 2em;
    color: #f0f0f0;
    display: block;
  }}
  .stat-label {{
    font-size: 0.75em;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 0.15em;
  }}
  .divider {{
    border: none;
    border-top: 1px solid #1a1a1a;
    margin: 40px 0;
  }}
  .install {{
    background: #111;
    border: 1px solid #222;
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 32px;
    text-align: left;
    font-size: 0.9em;
  }}
  .install code {{
    color: #aaa;
  }}
  .install .cmd {{
    color: #e0e0e0;
  }}
  .install .comment {{
    color: #444;
  }}
  .links {{
    display: flex;
    justify-content: center;
    gap: 24px;
    margin-bottom: 40px;
    flex-wrap: wrap;
  }}
  .links a {{
    color: #888;
    text-decoration: none;
    border-bottom: 1px solid #333;
    padding-bottom: 2px;
    transition: color 0.2s, border-color 0.2s;
    font-size: 0.9em;
  }}
  .links a:hover {{
    color: #f0f0f0;
    border-color: #666;
  }}
  .footer {{
    color: #333;
    font-size: 0.75em;
    margin-top: 48px;
    line-height: 1.8;
  }}
  .footer a {{
    color: #444;
    text-decoration: none;
  }}
  .pulse {{
    display: inline-block;
    width: 6px;
    height: 6px;
    background: #2a5;
    border-radius: 50%;
    margin-right: 6px;
    animation: pulse 2s infinite;
  }}
  @keyframes pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.3; }}
  }}
</style>
</head>
<body>
<div class="container">

  <h1>nur</h1>
  <div class="arabic">نور</div>
  <div class="tagline">
    collective security intelligence for industries.<br>
    give data, get smarter.
  </div>

  <div class="stats">
    <div class="stat">
      <span class="stat-num">{total}</span>
      <span class="stat-label">contributions</span>
    </div>
    <div class="stat">
      <span class="stat-num">{iocs + attacks}</span>
      <span class="stat-label">threat signals</span>
    </div>
    <div class="stat">
      <span class="stat-num">{vendors}</span>
      <span class="stat-label">vendors tracked</span>
    </div>
    <div class="stat">
      <span class="stat-num">37</span>
      <span class="stat-label">data sources</span>
    </div>
  </div>

  <div class="install">
    <code>
      <span class="comment"># install</span><br>
      <span class="cmd">pip install nur</span><br><br>
      <span class="comment"># connect</span><br>
      <span class="cmd">nur init</span><br><br>
      <span class="comment"># give data, get intelligence</span><br>
      <span class="cmd">nur report incident.json</span>
    </code>
  </div>

  <div class="links">
    <a href="/docs">api docs</a>
    <a href="https://github.com/manizzle/nur">github</a>
    <a href="https://github.com/manizzle/nur/issues/4">add your feed</a>
    <a href="/stats">live stats</a>
  </div>

  <hr class="divider">

  <div class="footer">
    <span class="pulse"></span> live &mdash; scraping 37 threat feeds<br><br>
    attackers share everything.<br>
    defenders share nothing.<br>
    nur fixes that.<br><br>
    <a href="https://github.com/manizzle/nur">apache 2.0</a> &bull;
    <a href="https://github.com/manizzle/nur/blob/main/DATA_LICENSE.md">cdla-permissive-2.0</a>
  </div>

</div>
</body>
</html>"""

    # ── Health ────────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    # ── Stats ─────────────────────────────────────────────────────────

    @app.get("/stats")
    async def stats():
        db = get_db()
        return await db.get_stats()

    # ── Contribute routes ─────────────────────────────────────────────

    @app.post("/contribute/submit")
    async def contribute_eval(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_eval_record(body)
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/attack-map")
    async def contribute_attack_map(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_attack_map(body)
        return {"status": "accepted", "contribution_id": cid}

    @app.post("/contribute/ioc-bundle")
    async def contribute_ioc_bundle(body: dict[str, Any]):
        db = get_db()
        cid = await db.store_ioc_bundle(body)
        return {"status": "accepted", "contribution_id": cid}

    # ── Analyze route ──────────────────────────────────────────────

    @app.post("/analyze")
    async def analyze(body: dict[str, Any]):
        db = get_db()
        from .analyze import (
            analyze_ioc_bundle, analyze_attack_map, analyze_eval_record,
            detect_contribution_type,
        )
        try:
            contrib_type = detect_contribution_type(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if contrib_type == "ioc_bundle":
            return await analyze_ioc_bundle(body, db)
        elif contrib_type == "attack_map":
            return await analyze_attack_map(body, db)
        elif contrib_type == "eval":
            return await analyze_eval_record(body, db)
        else:
            raise HTTPException(status_code=400, detail="Unknown contribution type")

    return app


# Default app instance for `uvicorn nur.server.app:app`
# Reads DB URL from NUR_DB_URL env var (for Docker deployment)
app = create_app(db_url=os.environ.get("NUR_DB_URL", "sqlite+aiosqlite:///nur.db"))
