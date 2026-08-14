"""Cloudflare edge integration.

WHAT THIS SOLVES
----------------
Behind Cloudflare every request arrives from a Cloudflare edge address, so the
socket peer is useless for identifying a client: without configuration, the
rate limiter would put the entire internet into a handful of buckets.

Cloudflare supplies the real client in `CF-Connecting-IP`. That header is only
meaningful if the request genuinely came from Cloudflare -- otherwise anyone can
set it and choose their own rate-limit identity. So the header is honoured only
when the socket peer is inside a published Cloudflare range, which is what the
list below is for.

WHY THE RANGES ARE PINNED IN SOURCE
-----------------------------------
Fetching them at startup would mean a network dependency on the boot path and,
worse, a failure mode where a DNS hiccup silently degrades the trust list --
trusting fewer proxies is safe, but trusting a *stale wrong* list is not. They
change rarely (a few times a decade). `scripts/refresh_cloudflare_ips.py`
re-fetches and rewrites this file so the update is an auditable diff rather
than invisible runtime behaviour.

Verified against https://www.cloudflare.com/ips/ -- see LAST_VERIFIED.
"""

from __future__ import annotations

LAST_VERIFIED = "2026-08-14"
SOURCE_V4 = "https://www.cloudflare.com/ips-v4"
SOURCE_V6 = "https://www.cloudflare.com/ips-v6"

# The header Cloudflare sets to the original client address. Unlike
# X-Forwarded-For this is a single value, not an appendable chain, so it cannot
# be polluted by an upstream hop.
CLOUDFLARE_CLIENT_IP_HEADER = "cf-connecting-ip"

IPV4_RANGES: tuple[str, ...] = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

IPV6_RANGES: tuple[str, ...] = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

ALL_RANGES: tuple[str, ...] = IPV4_RANGES + IPV6_RANGES

# Token accepted in TRUSTED_PROXIES as shorthand for the whole list. Spelling
# out fifteen CIDRs in an environment variable is exactly the kind of thing that
# gets truncated, mistyped, or half-updated.
TOKEN = "cloudflare"


def expand(entries: list[str]) -> list[str]:
    """Replace the `cloudflare` token with the published ranges.

    Any other entry is passed through untouched, so a deployment can trust
    Cloudflare *and* an internal load balancer:

        TRUSTED_PROXIES=cloudflare,10.0.0.0/8
    """
    expanded: list[str] = []
    for entry in entries:
        if entry.strip().lower() == TOKEN:
            expanded.extend(ALL_RANGES)
        else:
            expanded.append(entry)
    return expanded
