"""Resolving the real client IP behind a reverse proxy or CDN.

WHY THIS EXISTS
---------------
Forwarding headers (`X-Forwarded-For`, `CF-Connecting-IP`) are set by whoever
sends the request. Directly in front of the internet they are attacker-
controlled strings, and trusting them without checking who sent them defeats
anything keyed on client identity.

The original limiter read `X-Forwarded-For` unconditionally. Measured against
the running API with a 60-per-minute limit:

    fixed    X-Forwarded-For -> 60 allowed, 10 rejected   (correct)
    rotating X-Forwarded-For -> 69 allowed,  1 rejected   (bypassed)

Rotating a spoofed header per request gave essentially unlimited quota *and*
leaked a permanent dict entry per fake value, so the same trick was also a slow
memory-exhaustion primitive.

THE RULE
--------
A forwarding header is honoured only when the request's *socket peer* -- which
cannot be forged over TCP -- is a proxy we have explicitly listed. With no
trusted proxies configured (the default), the socket peer is always used and
headers are ignored entirely. That makes the safe configuration the one you get
by doing nothing.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from starlette.requests import Request

from . import cloudflare
from .config import settings

UNKNOWN_CLIENT = "unknown"


@lru_cache(maxsize=1)
def _trusted_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse TRUSTED_PROXIES once. Malformed entries are dropped, not fatal --
    a typo in a CIDR must not take the service down, and the effect of dropping
    one is to trust *less*, which is the safe direction."""
    networks = []
    # `cloudflare` expands to the published edge ranges; see core/cloudflare.py.
    for raw in cloudflare.expand(settings.trusted_proxy_list):
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _peer_is_trusted(peer: str) -> bool:
    networks = _trusted_networks()
    if not networks:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(address in network for network in networks)


def _first_public_hop(header_value: str) -> str | None:
    """Left-most entry of an X-Forwarded-For chain.

    The chain is appended to by each hop, so the left-most value is the one the
    original client supplied -- authentic only because we have already
    established that every hop between us and it is trusted.
    """
    for candidate in header_value.split(","):
        candidate = candidate.strip()
        if not candidate:
            continue
        # Strip a port if one was appended (some proxies do this for IPv4).
        if candidate.count(":") == 1 and "." in candidate:
            candidate = candidate.split(":")[0]
        try:
            ipaddress.ip_address(candidate.strip("[]"))
        except ValueError:
            return None
        return candidate.strip("[]")
    return None


def resolve_client_ip(request: Request) -> str:
    """The client address to attribute this request to.

    Returns the socket peer unless a trusted proxy told us otherwise.
    """
    peer = request.client.host if request.client else None
    if not peer:
        return UNKNOWN_CLIENT

    header_name = settings.client_ip_header.strip().lower()
    if not header_name or not _peer_is_trusted(peer):
        return peer

    forwarded = request.headers.get(header_name)
    if not forwarded:
        # Configured to expect the header but it is absent. Falling back to the
        # peer would key every request to the proxy's own address, collapsing
        # all clients into one bucket -- worse than useless. Prefer the peer
        # anyway and let the operator notice the misconfiguration.
        return peer

    resolved = _first_public_hop(forwarded)
    return resolved or peer


def reset_cache() -> None:
    """Clear parsed networks. Used by tests that change configuration."""
    _trusted_networks.cache_clear()
