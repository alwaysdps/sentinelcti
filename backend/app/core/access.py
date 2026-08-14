"""Optional shared-token access gate.

WHY THIS EXISTS
---------------
The platform has no user accounts by design -- the threat-analysis engine is
the point, and a half-built auth system would imply guarantees it could not
keep. That is fine on localhost. It stops being fine the moment the app is
published through a tunnel: the API has a DELETE endpoint and a real database
behind it, so "no authentication" becomes "anyone with the URL can erase the
data".

Cloudflare Access is the right answer for a permanent deployment (real identity,
no application code). It needs a domain. This gate covers the case in between:
a Quick Tunnel or a temporary demo, where something has to stand between the
public internet and a destructive endpoint *today*.

WHAT IT IS AND IS NOT
---------------------
It is a single shared secret checked in constant time, disabled unless
`ACCESS_TOKEN` is set. It is not user management, not sessions, not roles, and
it does not pretend to be: one token, held by whoever you gave it to, with no
way to revoke it individually. It raises the bar from "anyone" to "anyone you
told", which for a temporary public URL is the difference that matters.

`ACCESS_PROTECTED_METHODS` chooses what it covers. The default (`*`) protects
everything; a list protects only those methods. That is what makes
"open to everyone, except deletion" expressible -- browsing and submission stay
completely public while a passer-by cannot empty the database.
"""

from __future__ import annotations

import hmac

from starlette.requests import Request

from .config import settings
from .errors import SentinelError

HTTP_UNAUTHORIZED = 401

# Always reachable: liveness and the SPA's own capability probe. Neither
# discloses analysis data, and gating them would break the health check and
# leave the UI unable to render its own error state.
ALWAYS_OPEN_PATHS = frozenset({"/api/health", "/", "/docs", "/redoc", "/openapi.json"})

# CORS preflight carries no credentials and must never be gated, or the browser
# rejects the real request before it is ever sent.
ALWAYS_OPEN_METHODS = frozenset({"OPTIONS"})


class AccessDenied(SentinelError):
    status_code = HTTP_UNAUTHORIZED
    code = "access_denied"


def is_enabled() -> bool:
    return bool(settings.access_token.strip())


def _presented_token(request: Request) -> str:
    """Accept either a bearer header or `X-Access-Token`.

    The query string is deliberately not accepted: it would put the secret into
    server logs, browser history and `Referer` headers.
    """
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.headers.get("x-access-token", "").strip()


def is_protected(method: str) -> bool:
    """Whether this HTTP method requires the token under current settings."""
    if not is_enabled():
        return False
    method = method.upper()
    if method in ALWAYS_OPEN_METHODS:
        return False
    protected = settings.protected_method_set
    return method in protected if protected else True


def check(request: Request) -> None:
    """Raise AccessDenied unless the request is permitted."""
    if not is_enabled():
        return

    if request.url.path in ALWAYS_OPEN_PATHS:
        return

    if not is_protected(request.method):
        return

    presented = _presented_token(request)
    # compare_digest: a naive `==` leaks the token prefix through timing, and a
    # token guessable one character at a time is not a secret.
    if presented and hmac.compare_digest(presented, settings.access_token.strip()):
        return

    raise AccessDenied(
        f"{request.method} requests require an access token on this instance. "
        "Supply it as an 'Authorization: Bearer <token>' or 'X-Access-Token' header."
    )


def posture() -> dict:
    """Non-secret description of what is gated, for /api/config.

    Reports which methods are protected, never the token. The UI needs this to
    decide whether to offer a token prompt at all -- otherwise a fully open
    instance would show a login form that gates nothing.
    """
    protected = sorted(settings.protected_method_set)
    return {
        "enabled": is_enabled(),
        "protected_methods": protected if protected else (["*"] if is_enabled() else []),
        "public_read": is_enabled() and bool(protected) and "GET" not in protected,
    }
