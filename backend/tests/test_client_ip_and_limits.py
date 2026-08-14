"""Client identification and rate limiting.

Regression tests for a measured bypass: the limiter read `X-Forwarded-For`
unconditionally, so rotating that header per request gave 69/70 requests
through against a 60-per-minute limit, and leaked a permanent bucket per fake
value. Identity must come from the socket peer unless a *trusted* proxy said
otherwise.
"""

from __future__ import annotations

import pytest
from starlette.datastructures import Headers

from app.core import client_ip
from app.core.client_ip import resolve_client_ip

CLOUDFLARE_RANGE = "173.245.48.0/20"
CLOUDFLARE_PEER = "173.245.48.9"
UNTRUSTED_PEER = "203.0.113.50"
REAL_CLIENT = "198.51.100.7"


class FakeRequest:
    """Minimal stand-in: resolve_client_ip only reads `.client` and `.headers`."""

    def __init__(self, peer: str | None, headers: dict[str, str] | None = None):
        self.client = type("C", (), {"host": peer})() if peer else None
        self.headers = Headers(headers or {})


@pytest.fixture(autouse=True)
def _reset_trusted_networks():
    client_ip.reset_cache()
    yield
    client_ip.reset_cache()


def configure(monkeypatch, *, proxies: str = "", header: str = "") -> None:
    from app.core import config

    monkeypatch.setattr(config.settings, "trusted_proxies", proxies)
    monkeypatch.setattr(config.settings, "client_ip_header", header)
    client_ip.reset_cache()


class TestDefaultIsSafe:
    """Doing nothing must yield the secure configuration."""

    def test_forwarding_headers_ignored_when_no_proxy_configured(self, monkeypatch):
        configure(monkeypatch)
        request = FakeRequest(UNTRUSTED_PEER, {"x-forwarded-for": "1.2.3.4"})
        assert resolve_client_ip(request) == UNTRUSTED_PEER

    def test_cf_header_ignored_when_no_proxy_configured(self, monkeypatch):
        configure(monkeypatch)
        request = FakeRequest(UNTRUSTED_PEER, {"cf-connecting-ip": "1.2.3.4"})
        assert resolve_client_ip(request) == UNTRUSTED_PEER

    def test_missing_peer_is_handled(self, monkeypatch):
        configure(monkeypatch)
        assert resolve_client_ip(FakeRequest(None)) == client_ip.UNKNOWN_CLIENT


class TestTrustedProxy:
    def test_header_honoured_from_a_trusted_peer(self, monkeypatch):
        configure(monkeypatch, proxies=CLOUDFLARE_RANGE, header="cf-connecting-ip")
        request = FakeRequest(CLOUDFLARE_PEER, {"cf-connecting-ip": REAL_CLIENT})
        assert resolve_client_ip(request) == REAL_CLIENT

    def test_header_rejected_from_an_untrusted_peer(self, monkeypatch):
        """The spoofing case: same header, sender not on the trust list."""
        configure(monkeypatch, proxies=CLOUDFLARE_RANGE, header="cf-connecting-ip")
        request = FakeRequest(UNTRUSTED_PEER, {"cf-connecting-ip": REAL_CLIENT})
        assert resolve_client_ip(request) == UNTRUSTED_PEER

    def test_falls_back_to_peer_when_header_absent(self, monkeypatch):
        configure(monkeypatch, proxies=CLOUDFLARE_RANGE, header="cf-connecting-ip")
        assert resolve_client_ip(FakeRequest(CLOUDFLARE_PEER)) == CLOUDFLARE_PEER

    def test_leftmost_hop_used_from_a_forwarded_chain(self, monkeypatch):
        configure(monkeypatch, proxies=CLOUDFLARE_RANGE, header="x-forwarded-for")
        request = FakeRequest(CLOUDFLARE_PEER, {"x-forwarded-for": f"{REAL_CLIENT}, 10.0.0.1"})
        assert resolve_client_ip(request) == REAL_CLIENT

    def test_garbage_header_falls_back_to_peer(self, monkeypatch):
        configure(monkeypatch, proxies=CLOUDFLARE_RANGE, header="x-forwarded-for")
        request = FakeRequest(CLOUDFLARE_PEER, {"x-forwarded-for": "not-an-ip"})
        assert resolve_client_ip(request) == CLOUDFLARE_PEER

    def test_port_suffix_is_stripped(self, monkeypatch):
        configure(monkeypatch, proxies=CLOUDFLARE_RANGE, header="x-forwarded-for")
        request = FakeRequest(CLOUDFLARE_PEER, {"x-forwarded-for": f"{REAL_CLIENT}:51234"})
        assert resolve_client_ip(request) == REAL_CLIENT

    def test_ipv6_client_is_resolved(self, monkeypatch):
        configure(monkeypatch, proxies="2400:cb00::/32", header="cf-connecting-ip")
        request = FakeRequest("2400:cb00::1", {"cf-connecting-ip": "2606:4700::1234"})
        assert resolve_client_ip(request) == "2606:4700::1234"

    def test_malformed_cidr_is_ignored_rather_than_fatal(self, monkeypatch):
        """A typo must reduce trust, never crash the service."""
        configure(monkeypatch, proxies="not-a-cidr, " + CLOUDFLARE_RANGE, header="cf-connecting-ip")
        request = FakeRequest(CLOUDFLARE_PEER, {"cf-connecting-ip": REAL_CLIENT})
        assert resolve_client_ip(request) == REAL_CLIENT

    def test_only_malformed_cidrs_means_trust_nothing(self, monkeypatch):
        configure(monkeypatch, proxies="not-a-cidr", header="cf-connecting-ip")
        request = FakeRequest(CLOUDFLARE_PEER, {"cf-connecting-ip": REAL_CLIENT})
        assert resolve_client_ip(request) == CLOUDFLARE_PEER


class TestRateLimitCannotBeBypassed:
    """The measured regression, reproduced through the real middleware."""

    @pytest.fixture
    def limited(self, client, monkeypatch):
        from app.core import config
        from app.core.middleware import reset_rate_limit_state

        monkeypatch.setattr(config.settings, "rate_limit_enabled", True)
        monkeypatch.setattr(config.settings, "rate_limit_requests", 5)
        monkeypatch.setattr(config.settings, "rate_limit_window_seconds", 60)
        configure(monkeypatch)  # no trusted proxies: the default posture
        # Each test needs a fresh window; otherwise it inherits whatever the
        # previous one consumed.
        reset_rate_limit_state()
        yield client
        reset_rate_limit_state()

    def test_limit_is_enforced(self, limited):
        codes = [limited.get("/api/config").status_code for _ in range(8)]
        assert codes.count(429) >= 3

    def test_rotating_forwarded_for_cannot_widen_the_limit(self, limited):
        codes = [
            limited.get("/api/config", headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code
            for i in range(8)
        ]
        assert codes.count(429) >= 3, "spoofed header granted extra quota"

    def test_rotating_cf_header_cannot_widen_the_limit(self, limited):
        codes = [
            limited.get("/api/config", headers={"CF-Connecting-IP": f"10.0.1.{i}"}).status_code
            for i in range(8)
        ]
        assert codes.count(429) >= 3

    def test_rate_limit_headers_are_present(self, limited):
        response = limited.get("/api/config")
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers

    def test_429_includes_retry_after(self, limited):
        last = None
        for _ in range(8):
            last = limited.get("/api/config")
        assert last.status_code == 429
        assert "Retry-After" in last.headers


class TestLimiterStateIsBounded:
    """A per-client structure must not become unbounded memory growth."""

    def build(self):
        from app.core.middleware import RateLimitMiddleware

        return RateLimitMiddleware(app=None)

    def test_sweep_drops_inactive_buckets(self):
        from collections import deque

        limiter = self.build()
        limiter._hits["stale"] = deque([0.0])
        limiter._hits["fresh"] = deque([1000.0])
        limiter._sweep(now=1000.0, window=60)
        assert "stale" not in limiter._hits
        assert "fresh" in limiter._hits

    def test_empty_buckets_are_dropped(self):
        from collections import deque

        limiter = self.build()
        limiter._hits["empty"] = deque()
        limiter._sweep(now=1.0, window=60)
        assert "empty" not in limiter._hits

    def test_tracked_clients_are_capped(self, monkeypatch):
        from collections import deque

        from app.core import config

        monkeypatch.setattr(config.settings, "rate_limit_max_tracked_clients", 10)
        limiter = self.build()
        # All active, so only the hard cap can bound this.
        for i in range(50):
            limiter._hits[f"c{i}"] = deque([1000.0 + i])
        limiter._sweep(now=1000.0, window=10_000)
        assert len(limiter._hits) <= 10

    def test_cap_evicts_the_least_recently_active(self, monkeypatch):
        from collections import deque

        from app.core import config

        monkeypatch.setattr(config.settings, "rate_limit_max_tracked_clients", 2)
        limiter = self.build()
        limiter._hits["old"] = deque([1.0])
        limiter._hits["mid"] = deque([500.0])
        limiter._hits["new"] = deque([999.0])
        limiter._sweep(now=1000.0, window=10_000)
        assert "new" in limiter._hits
        assert "old" not in limiter._hits
