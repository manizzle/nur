"""
Vendor intelligence scrapers — ported from bakeoff.

Each scraper exports a `scrape(config)` function that returns a list of
tool evaluation dicts. These complement the IOC feeds in oombra/feeds.py.

Registry:
  SCRAPERS — dict mapping scraper name to {scraper, description}.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Callable

from .mitre import scrape as scrape_mitre
from .cisa_kev import scrape as scrape_cisa_kev_vendors
from .reddit import scrape as scrape_reddit
from .hackernews import scrape as scrape_hackernews
from .avtest import scrape as scrape_avtest
from .selabs import scrape as scrape_selabs
from .vendor_meta import scrape as scrape_vendor_meta


SCRAPERS: dict[str, dict[str, Any]] = {
    "mitre": {
        "scraper": scrape_mitre,
        "description": "MITRE ATT&CK Evaluations (public EDR benchmarks)",
    },
    "cisa-kev-vendors": {
        "scraper": scrape_cisa_kev_vendors,
        "description": "CISA KEV cross-referenced with security vendors",
    },
    "reddit": {
        "scraper": scrape_reddit,
        "description": "Reddit community intelligence (r/netsec, r/cybersecurity)",
    },
    "hackernews": {
        "scraper": scrape_hackernews,
        "description": "Hacker News security tool discussions",
    },
    "avtest": {
        "scraper": scrape_avtest,
        "description": "AV-TEST independent lab results",
    },
    "selabs": {
        "scraper": scrape_selabs,
        "description": "SE Labs endpoint protection results",
    },
    "vendor-meta": {
        "scraper": scrape_vendor_meta,
        "description": "Vendor metadata (pricing, certs, insurance)",
    },
}


def run_scraper(name: str) -> list[dict]:
    """Run a single scraper by name. Returns list of evaluation dicts."""
    if name not in SCRAPERS:
        raise ValueError(f"Unknown scraper: {name!r}. Available: {', '.join(SCRAPERS)}")
    return SCRAPERS[name]["scraper"]()


def run_all_scrapers() -> dict[str, list[dict]]:
    """Run all scrapers. Returns {scraper_name: [eval_dicts]}."""
    results: dict[str, list[dict]] = {}
    for name in SCRAPERS:
        try:
            results[name] = run_scraper(name)
        except Exception:
            results[name] = []
    return results


def ingest_evals_to_server(
    api_url: str,
    evals: list[dict],
    api_key: str | None = None,
) -> int:
    """
    POST vendor evaluation dicts to /contribute/submit on the oombra server.
    Returns count of successful uploads.
    """
    url = f"{api_url.rstrip('/')}/contribute/submit"
    ok = 0
    for ev in evals:
        payload = json.dumps(ev).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        if api_key:
            req.add_header("X-API-Key", api_key)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status < 300:
                    ok += 1
        except Exception:
            continue
    return ok
