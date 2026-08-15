"""Anonymous per-browser workspaces.

WHAT THIS IS
------------
Every visitor gets a private view of their own submissions without creating an
account. The browser generates a random key on first use, keeps it in local
storage, and sends it with each request; the server stamps it onto each
analysis and filters every read by it.

WHAT THIS IS NOT
----------------
It is **isolation, not authentication**. Nothing proves the caller is the same
person who created a workspace -- only that they hold the key. Specifically:

* anyone who obtains a key sees that workspace (so the key is 256 bits of
  randomness, never logged, and never placed in a URL where it would leak
  through `Referer`, browser history and server access logs);
* clearing site data loses the workspace, because the key lived only there;
* a workspace is per browser, not per person -- the same user on a phone and a
  laptop has two.

That is the deliberate trade for having no login at all. Anything stronger
needs real accounts, which is a different feature with a different cost.

SHARED DEMO DATA
----------------
Seeded rows (`is_demo`) belong to no workspace and are visible to everyone, so
a first-time visitor sees a populated dashboard rather than an empty one. They
are read-only for the same reason: nobody owns them, so nobody may delete them.
"""

from __future__ import annotations

import re

from starlette.requests import Request

# Sent as a header, never a query parameter: a key in the URL leaks into server
# logs, browser history and the Referer sent to any third party.
OWNER_HEADER = "x-owner-key"

# 32-64 chars of URL-safe text. Broad enough to accept a UUID or a hex/base64
# token, tight enough to reject junk before it reaches the database.
_VALID_KEY = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


def resolve_owner_key(request: Request) -> str | None:
    """The caller's workspace key, or None if absent or malformed.

    None means "no workspace": the caller sees only shared demo data and any
    analysis they create is unowned. That is the correct degradation for a
    client with storage disabled -- the tool still works, it just does not
    remember.
    """
    raw = request.headers.get(OWNER_HEADER, "").strip()
    return raw if _VALID_KEY.match(raw) else None


def is_valid_key(value: str | None) -> bool:
    return bool(value and _VALID_KEY.match(value))
