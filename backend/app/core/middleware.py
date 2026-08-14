"""Cross-cutting HTTP middleware: request size caps, rate limiting, headers.

Implemented in-process on purpose. A single-node MVP does not need Redis, and
an in-memory limiter is honest about its scope -- the README documents that a
shared store is required once the API runs behind more than one worker.
"""

from __future__ import annotations

import time
import weakref
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .client_ip import resolve_client_ip
from . import access
from .config import settings

# Weak so a discarded app does not pin its middleware in memory.
_LIMITER_INSTANCES: weakref.WeakSet = weakref.WeakSet()


def reset_rate_limit_state() -> None:
    """Clear every limiter's buckets. For tests, which would otherwise inherit
    an exhausted window from whichever test ran before them."""
    for limiter in list(_LIMITER_INSTANCES):
        limiter._hits.clear()
        limiter._requests_since_sweep = 0


class AccessGateMiddleware(BaseHTTPMiddleware):
    """Enforce the optional shared-token gate.

    Middleware rather than a route dependency so that nothing can be added
    later that forgets to opt in -- a new router is covered the moment it is
    mounted. No-ops entirely unless ACCESS_TOKEN is set.
    """

    async def dispatch(self, request: Request, call_next):
        try:
            access.check(request)
        except access.AccessDenied as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"error": {"code": exc.code, "message": exc.message}},
            )
        return await call_next(request)


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies from the declared Content-Length.

    This is a cheap first gate. The file analyzer independently enforces the
    real limit while streaming, because Content-Length is attacker-controlled.
    """

    async def dispatch(self, request: Request, call_next):
        raw = request.headers.get("content-length")
        if raw and raw.isdigit() and int(raw) > settings.max_request_bytes:
            return JSONResponse(
                status_code=413,
                content={
                    "error": {
                        "code": "payload_too_large",
                        "message": f"Request body exceeds {settings.max_request_bytes} bytes.",
                    }
                },
            )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding window limiter keyed by the client's real address.

    Two properties this must hold, both of which the first implementation got
    wrong (see core/client_ip.py for the measurements):

    * **The key must not be forgeable.** Identity comes from the socket peer
      unless a *trusted* proxy supplied a forwarding header. Otherwise anyone
      rotating `X-Forwarded-For` gets unlimited quota.
    * **State must be bounded.** The bucket map is swept and capped, so a
      caller cannot turn a per-client structure into unbounded memory growth.
    """

    # Sweeping on every request would be wasteful; every N is enough to keep
    # the map proportional to *active* clients rather than to all clients ever.
    SWEEP_EVERY_N_REQUESTS = 256

    def __init__(self, app) -> None:
        super().__init__(app)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._requests_since_sweep = 0
        # Starlette builds the middleware stack internally, so there is no
        # supported way to reach this instance afterwards. A weak registry
        # gives tests a reset handle without keeping the object alive.
        _LIMITER_INSTANCES.add(self)

    def _sweep(self, now: float, window: float) -> None:
        """Drop buckets with no activity inside the window."""
        stale = [key for key, hits in self._hits.items() if not hits or now - hits[-1] > window]
        for key in stale:
            del self._hits[key]

        # Hard ceiling in case sweeping cannot keep up with a burst of unique
        # clients. Evicting the least-recently-active is the least harmful
        # choice: the evicted caller simply gets a fresh window.
        overflow = len(self._hits) - settings.rate_limit_max_tracked_clients
        if overflow > 0:
            oldest = sorted(self._hits, key=lambda k: self._hits[k][-1] if self._hits[k] else 0.0)
            for key in oldest[:overflow]:
                del self._hits[key]

    async def dispatch(self, request: Request, call_next):
        if not settings.rate_limit_enabled or request.method == "OPTIONS":
            return await call_next(request)

        key = resolve_client_ip(request)
        now = time.monotonic()
        window = settings.rate_limit_window_seconds

        self._requests_since_sweep += 1
        if self._requests_since_sweep >= self.SWEEP_EVERY_N_REQUESTS:
            self._requests_since_sweep = 0
            self._sweep(now, window)

        bucket = self._hits[key]

        while bucket and now - bucket[0] > window:
            bucket.popleft()

        if len(bucket) >= settings.rate_limit_requests:
            retry_after = int(window - (now - bucket[0])) + 1
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "error": {
                        "code": "rate_limited",
                        "message": "Too many requests. Slow down and retry shortly.",
                    }
                },
            )

        bucket.append(now)
        response: Response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, settings.rate_limit_requests - len(bucket))
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Baseline hardening headers for the JSON API."""

    # Swagger UI / ReDoc are HTML pages that legitimately load scripts and
    # styles; the strict JSON-only CSP below would blank them out.
    DOC_PATHS = ("/docs", "/redoc", "/openapi.json")

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.url.path.startswith(self.DOC_PATHS):
            # The API serves JSON only; a maximally restrictive CSP costs
            # nothing and blocks rendering of anything reflected by a bug.
            response.headers.setdefault(
                "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
            )
        return response
