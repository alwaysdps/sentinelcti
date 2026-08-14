"""Bounded, passive DNS helpers.

Resolution talks to the configured resolver, not to the indicator itself, so it
leaks nothing to the operator of a suspicious domain beyond a cache query. It
is still optional (`ENABLE_DNS_LOOKUPS`) and hard-bounded by a timeout, because
an analyzer must never be able to hang a request.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from ..core.config import settings


@dataclass
class DnsResult:
    attempted: bool = False
    resolved: bool = False
    addresses: list[str] = field(default_factory=list)
    error: str | None = None
    reverse_name: str | None = None


def resolve_hostname(host: str) -> DnsResult:
    result = DnsResult()
    if not settings.enable_dns_lookups:
        return result

    result.attempted = True
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(settings.dns_timeout_seconds)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        # Deduplicate while preserving resolver ordering, which carries meaning
        # (round-robin / preference).
        seen: list[str] = []
        for info in infos:
            address = info[4][0]
            if address not in seen:
                seen.append(address)
        result.addresses = seen
        result.resolved = bool(seen)
    except socket.gaierror as exc:
        result.error = f"DNS resolution failed: {exc.strerror or exc}"
    except (socket.timeout, OSError) as exc:
        result.error = f"DNS lookup unavailable: {exc}"
    finally:
        socket.setdefaulttimeout(original_timeout)
    return result


def reverse_lookup(ip: str) -> DnsResult:
    result = DnsResult()
    if not settings.enable_dns_lookups:
        return result

    result.attempted = True
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(settings.dns_timeout_seconds)
    try:
        hostname, _aliases, addresses = socket.gethostbyaddr(ip)
        result.reverse_name = hostname
        result.addresses = list(addresses)
        result.resolved = True
    except (socket.herror, socket.gaierror):
        result.error = "No PTR record found."
    except (socket.timeout, OSError) as exc:
        result.error = f"Reverse lookup unavailable: {exc}"
    finally:
        socket.setdefaulttimeout(original_timeout)
    return result
