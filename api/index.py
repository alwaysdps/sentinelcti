"""Vercel serverless entrypoint for the SentinelCTI API.

Vercel treats every file under `/api` as a function and speaks ASGI natively,
so this module only has to expose the existing FastAPI application — there is
no second copy of the app and no parallel routing table to keep in sync.

WHAT CHANGES ON SERVERLESS
--------------------------
Three of the platform's guarantees depend on a long-running process, and this
is the honest accounting of what happens without one:

* **In-process rate limiting stops binding.** Each invocation has its own
  memory, so the sliding window resets constantly. Cloudflare rate limiting on
  the API hostname is the replacement -- see README section 12.4. Leaving the
  in-process limiter enabled is still worth it: it bounds a single warm
  instance and costs nothing.

* **The quarantine disk budget becomes per-invocation.** Uploads are deleted
  immediately after analysis, so nothing accumulates; the ceiling simply stops
  being a global one. `UPLOAD_DIR` must point at `/tmp`, the only writable path.

* **The analysis budget can outlive the function.** A Hobby function is capped
  at 10s by default, which is also the analyzer's own budget -- so a
  pathological sample may be cut short by the platform rather than producing
  the truncated-but-labelled report it would on a container. Raising
  `maxDuration` (see vercel.json) restores the intended behaviour.

Required environment variables in the Vercel project:

    DATABASE_URL              Supabase transaction pooler URI (port 6543)
    DATABASE_DISABLE_POOLING  true   -- a client pool cannot be reused here
    AUTO_CREATE_TABLES        false  -- schema already exists; skip the
                                       reflection round-trip on every cold start
    UPLOAD_DIR                /tmp/quarantine
    CORS_ORIGINS              https://<your-domain>,https://<project>.vercel.app
    ENVIRONMENT               production
    DEBUG                     false
"""

from __future__ import annotations

import sys
from pathlib import Path

# The application package lives in backend/, outside this directory. Vercel
# ships it because vercel.json lists it under includeFiles.
BACKEND_ROOT = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.main import app  # noqa: E402

# Vercel's Python runtime looks for a module-level ASGI callable named `app`.
__all__ = ["app"]
