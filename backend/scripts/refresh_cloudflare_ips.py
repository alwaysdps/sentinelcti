"""Refresh the pinned Cloudflare edge ranges in `app/core/cloudflare.py`.

Run this occasionally (Cloudflare changes the list rarely) and commit the diff.
Doing it as a source rewrite rather than a startup fetch is deliberate: the
trust list is a security control, so a change to it should appear in review as
an explicit diff, not happen invisibly at boot.

    python -m scripts.refresh_cloudflare_ips           # show what would change
    python -m scripts.refresh_cloudflare_ips --write   # apply it

Safety: the file is only rewritten if both endpoints return a plausible list.
An empty or malformed response leaves the pinned values in place -- a partial
overwrite would silently shrink the trusted set and break client-IP resolution.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core import cloudflare  # noqa: E402

TARGET = Path(__file__).resolve().parents[1] / "app" / "core" / "cloudflare.py"
TIMEOUT = 15
# Sanity floors: the published lists have had roughly this many entries for
# years. A response far below these means something is wrong upstream.
MIN_V4, MIN_V6 = 10, 5


def fetch(url: str) -> list[str]:
    request = urllib.request.Request(url, headers={"User-Agent": "SentinelCTI/refresh-ips"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        body = response.read().decode("utf-8", "replace")

    ranges: list[str] = []
    for line in body.splitlines():
        entry = line.strip()
        if not entry:
            continue
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        ranges.append(entry)
    return ranges


def render_tuple(name: str, values: list[str]) -> str:
    body = "".join(f'    "{value}",\n' for value in values)
    return f"{name}: tuple[str, ...] = (\n{body})"


def main(write: bool) -> int:
    try:
        v4 = fetch(cloudflare.SOURCE_V4)
        v6 = fetch(cloudflare.SOURCE_V6)
    except Exception as exc:  # noqa: BLE001 - report, never half-apply
        print(f"[fail] Could not fetch ranges: {type(exc).__name__}: {exc}")
        print("  -> Pinned values left unchanged.")
        return 1

    if len(v4) < MIN_V4 or len(v6) < MIN_V6:
        print(f"[fail] Implausible response ({len(v4)} IPv4, {len(v6)} IPv6).")
        print("  -> Refusing to shrink the trusted set. Pinned values unchanged.")
        return 1

    current_v4, current_v6 = list(cloudflare.IPV4_RANGES), list(cloudflare.IPV6_RANGES)
    added = sorted((set(v4) | set(v6)) - (set(current_v4) | set(current_v6)))
    removed = sorted((set(current_v4) | set(current_v6)) - (set(v4) | set(v6)))

    print(f"Fetched {len(v4)} IPv4 + {len(v6)} IPv6 ranges")
    print(f"Pinned  {len(current_v4)} IPv4 + {len(current_v6)} IPv6 ranges (verified {cloudflare.LAST_VERIFIED})")

    if not added and not removed:
        print("\n[ ok ] Pinned ranges are current. Nothing to do.")
        return 0

    for entry in added:
        print(f"  + {entry}")
    for entry in removed:
        print(f"  - {entry}")

    if not write:
        print("\nRe-run with --write to apply, then commit the diff.")
        return 0

    source = TARGET.read_text(encoding="utf-8")
    source = re.sub(
        r'IPV4_RANGES: tuple\[str, \.\.\.\] = \([^)]*\)', render_tuple("IPV4_RANGES", v4), source
    )
    source = re.sub(
        r'IPV6_RANGES: tuple\[str, \.\.\.\] = \([^)]*\)', render_tuple("IPV6_RANGES", v6), source
    )
    source = re.sub(
        r'LAST_VERIFIED = "[^"]*"',
        f'LAST_VERIFIED = "{dt.date.today().isoformat()}"',
        source,
    )
    TARGET.write_text(source, encoding="utf-8")
    print(f"\n[ ok ] Wrote {TARGET.relative_to(Path.cwd()) if TARGET.is_relative_to(Path.cwd()) else TARGET}")
    print("  -> Review the diff and run the tests before committing.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Apply the update.")
    raise SystemExit(main(parser.parse_args().write))
