"""SentinelCTI API entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import api_router
from .core.config import settings
from .core.errors import register_exception_handlers
from .core.middleware import (
    AccessGateMiddleware,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from .database import init_db

logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
)
logger = logging.getLogger("sentinelcti")

DESCRIPTION = """
**SentinelCTI** is a defensive cyber threat intelligence platform for triaging
suspicious files, URLs and network indicators.

### What it does
Submit a URL, domain, IP address, file hash or file. Each indicator is run
through a type-specific analyzer that produces named, explainable *findings*,
enriched by pluggable threat-intelligence providers, and scored by a
transparent risk engine. The report shows exactly which findings contributed
which points.

### What it deliberately does not do
* Uploaded files are **never executed**, extracted or parsed by a format handler.
  Analysis is strictly static: hashing, magic-byte identification, entropy and
  string pattern matching.
* Submitted URLs are **never fetched**. No crawling, no redirect following.
* Submitted IP addresses are **never contacted**. No ping, no port scan.

### Risk Score, not malware probability
The score is a reproducible weighted sum of documented heuristics. It is not
calibrated against a labelled corpus and must not be read as a probability of
maliciousness. Every point is traceable to a named finding.

### MITRE ATT&CK
Technique associations are labelled *potential association*. A string inside a
file shows a capability is referenced; it never proves the technique executed.
"""

TAGS_METADATA = [
    {"name": "System", "description": "Health, dashboard aggregates and platform capabilities."},
    {"name": "Analysis", "description": "Submit an indicator for analysis."},
    {"name": "History", "description": "Retrieve, search and delete stored analyses."},
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_tables:
        init_db()

    try:
        settings.upload_dir.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError) as exc:
        # OSError covers the read-only filesystem; ValueError covers a path the
        # OS refuses outright (an embedded NUL, say). Either way the response is
        # the same -- warn and carry on, because the upload directory is not a
        # prerequisite for the endpoints that never touch it.
        # Serverless filesystems are read-only apart from /tmp. Failing startup
        # here would take down an API whose non-file endpoints work perfectly
        # well; the file route raises its own clear error if it cannot write.
        logger.warning(
            "Quarantine directory %s is not writable (%s). File uploads will "
            "fail until UPLOAD_DIR points somewhere writable, such as /tmp.",
            settings.upload_dir,
            exc,
        )
    logger.info(
        "SentinelCTI %s starting (env=%s, providers=%s)",
        settings.app_version,
        settings.environment,
        ",".join(settings.provider_list) or "none",
    )
    yield
    logger.info("SentinelCTI shutting down")


app = FastAPI(
    title=f"{settings.app_name} API",
    version=settings.app_version,
    description=DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    contact={"name": "SentinelCTI", "url": "https://github.com/"},
    license_info={"name": "MIT"},
)

# Middleware executes bottom-up, so declare the cheapest rejection last: a body
# that is too large is refused before the rate limiter even accounts for it.
app.add_middleware(SecurityHeadersMiddleware)
# Above the rate limiter: an unauthenticated request should be refused
# without consuming the caller's quota.
app.add_middleware(AccessGateMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    # Explicit origins, never "*": the API is credential-free today, but a
    # wildcard would silently become a hole the moment auth is added.
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)

register_exception_handlers(app)
app.include_router(api_router)


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/api/health",
    }
