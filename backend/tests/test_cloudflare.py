"""Cloudflare edge integration.

The property under test is narrow but load-bearing: `CF-Connecting-IP` decides
who a request is attributed to, so it must be honoured when -- and only when --
the request actually came from Cloudflare. Get it wrong in one direction and
every visitor collapses into one rate-limit bucket; wrong in the other and
anyone can pick their own identity by setting a header.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.core import client_ip, cloudflare


@pytest.fixture(autouse=True)
def _reset_trust_cache():
    client_ip.reset_cache()
    yield
    client_ip.reset_cache()


def configure(monkeypatch, *, proxies: str, header: str = ""):
    from app.core import config

    monkeypatch.setattr(config.settings, "trusted_proxies", proxies)
    monkeypatch.setattr(config.settings, "client_ip_header", header)
    client_ip.reset_cache()


class FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class FakeRequest:
    """Minimal stand-in: resolve_client_ip only reads .client and .headers."""

    def __init__(self, peer: str | None, headers: dict[str, str] | None = None) -> None:
        self.client = FakeClient(peer) if peer else None
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}


# A real Cloudflare edge address (inside 104.16.0.0/13) and a non-Cloudflare one.
CF_EDGE = "104.16.5.5"
NOT_CF = "203.0.113.9"
REAL_CLIENT = "198.51.100.44"


class TestPinnedRanges:
    def test_ranges_are_valid_cidrs(self):
        for entry in cloudflare.ALL_RANGES:
            ipaddress.ip_network(entry, strict=False)

    def test_families_are_not_mixed_up(self):
        assert all(ipaddress.ip_network(e).version == 4 for e in cloudflare.IPV4_RANGES)
        assert all(ipaddress.ip_network(e).version == 6 for e in cloudflare.IPV6_RANGES)

    def test_no_duplicates(self):
        assert len(set(cloudflare.ALL_RANGES)) == len(cloudflare.ALL_RANGES)

    def test_no_overly_broad_range_slipped_in(self):
        """A /0 or a very short prefix would trust most of the internet."""
        for entry in cloudflare.ALL_RANGES:
            network = ipaddress.ip_network(entry)
            floor = 8 if network.version == 4 else 20
            assert network.prefixlen >= floor, f"{entry} is implausibly broad"

    def test_no_private_space_in_the_trust_list(self):
        for entry in cloudflare.ALL_RANGES:
            assert not ipaddress.ip_network(entry).is_private, entry


class TestTokenExpansion:
    def test_token_expands_to_every_range(self, monkeypatch):
        assert set(cloudflare.expand(["cloudflare"])) == set(cloudflare.ALL_RANGES)

    def test_token_is_case_insensitive(self):
        assert cloudflare.expand(["CloudFlare"]) == list(cloudflare.ALL_RANGES)

    def test_other_entries_pass_through(self):
        expanded = cloudflare.expand(["10.0.0.0/8", "cloudflare"])
        assert "10.0.0.0/8" in expanded
        assert cloudflare.IPV4_RANGES[0] in expanded

    def test_no_token_means_no_expansion(self):
        assert cloudflare.expand(["10.0.0.0/8"]) == ["10.0.0.0/8"]


class TestClientAttribution:
    def test_cf_header_is_honoured_from_a_cloudflare_edge(self, monkeypatch):
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        request = FakeRequest(CF_EDGE, {"CF-Connecting-IP": REAL_CLIENT})
        assert client_ip.resolve_client_ip(request) == REAL_CLIENT

    def test_cf_header_is_ignored_from_a_non_cloudflare_peer(self, monkeypatch):
        """The whole point: anyone can set the header, so the peer decides."""
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        request = FakeRequest(NOT_CF, {"CF-Connecting-IP": "1.2.3.4"})
        assert client_ip.resolve_client_ip(request) == NOT_CF

    def test_spoofed_header_cannot_rotate_identity(self, monkeypatch):
        """Rotating a spoofed header previously granted unlimited rate quota."""
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        keys = {
            client_ip.resolve_client_ip(FakeRequest(NOT_CF, {"CF-Connecting-IP": f"9.9.9.{i}"}))
            for i in range(20)
        }
        assert keys == {NOT_CF}, "spoofed header changed the rate-limit key"

    def test_default_configuration_trusts_nothing(self, monkeypatch):
        """Doing nothing must be the safe configuration."""
        configure(monkeypatch, proxies="", header="")
        request = FakeRequest(NOT_CF, {"CF-Connecting-IP": "1.2.3.4"})
        assert client_ip.resolve_client_ip(request) == NOT_CF

    def test_missing_header_from_a_trusted_edge_falls_back_to_peer(self, monkeypatch):
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        assert client_ip.resolve_client_ip(FakeRequest(CF_EDGE)) == CF_EDGE

    def test_garbage_header_value_falls_back_to_peer(self, monkeypatch):
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        request = FakeRequest(CF_EDGE, {"CF-Connecting-IP": "definitely-not-an-ip"})
        assert client_ip.resolve_client_ip(request) == CF_EDGE

    def test_ipv6_edge_is_recognised(self, monkeypatch):
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        request = FakeRequest("2606:4700::1", {"CF-Connecting-IP": REAL_CLIENT})
        assert client_ip.resolve_client_ip(request) == REAL_CLIENT

    def test_cloudflare_and_an_internal_proxy_can_coexist(self, monkeypatch):
        configure(monkeypatch, proxies="cloudflare,10.0.0.0/8", header="cf-connecting-ip")
        assert (
            client_ip.resolve_client_ip(FakeRequest("10.1.2.3", {"CF-Connecting-IP": REAL_CLIENT}))
            == REAL_CLIENT
        )
        assert (
            client_ip.resolve_client_ip(FakeRequest(CF_EDGE, {"CF-Connecting-IP": REAL_CLIENT}))
            == REAL_CLIENT
        )

    def test_missing_socket_peer_is_handled(self, monkeypatch):
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        assert client_ip.resolve_client_ip(FakeRequest(None)) == client_ip.UNKNOWN_CLIENT


class TestEdgeStatusReporting:
    """A proxy misconfiguration has no runtime symptom -- rate limiting still
    runs, it just stops distinguishing clients. So it is reported instead."""

    def test_default_reports_socket_peer(self, client, monkeypatch):
        configure(monkeypatch, proxies="", header="")
        edge = client.get("/api/config").json()["edge"]
        assert edge["forwarding_headers_trusted"] is False
        assert "socket peer" in edge["client_ip_source"]
        assert edge["warning"] is None

    def test_cloudflare_configuration_is_reported(self, client, monkeypatch):
        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        edge = client.get("/api/config").json()["edge"]
        assert edge["behind_cloudflare"] is True
        assert edge["forwarding_headers_trusted"] is True
        assert edge["trusted_proxy_count"] == len(cloudflare.ALL_RANGES)
        assert edge["warning"] is None

    def test_header_without_trusted_proxies_is_flagged(self, client, monkeypatch):
        """Looks configured, silently does nothing."""
        configure(monkeypatch, proxies="", header="cf-connecting-ip")
        edge = client.get("/api/config").json()["edge"]
        assert edge["forwarding_headers_trusted"] is False
        assert "TRUSTED_PROXIES is empty" in edge["warning"]

    def test_trusted_proxies_without_header_is_flagged(self, client, monkeypatch):
        """Collapses every client behind the proxy into one bucket."""
        configure(monkeypatch, proxies="cloudflare", header="")
        edge = client.get("/api/config").json()["edge"]
        assert edge["forwarding_headers_trusted"] is False
        assert "one rate-limit bucket" in edge["warning"]

    def test_edge_status_never_exposes_the_proxy_list(self, client, monkeypatch):
        """Posture, not configuration detail."""
        configure(monkeypatch, proxies="cloudflare,10.1.2.0/24", header="cf-connecting-ip")
        body = client.get("/api/config").text
        assert "10.1.2.0/24" not in body
        assert "104.16.0.0/13" not in body


class TestRateLimitIntegration:
    def test_requests_behind_cloudflare_are_bucketed_per_client(self, monkeypatch, client):
        """Without CF-Connecting-IP handling every visitor shares one bucket,
        so one busy user would rate-limit the whole internet."""
        from app.core import config

        configure(monkeypatch, proxies="cloudflare", header="cf-connecting-ip")
        monkeypatch.setattr(config.settings, "rate_limit_enabled", True)
        monkeypatch.setattr(config.settings, "rate_limit_requests", 5)

        from app.core.middleware import reset_rate_limit_state

        reset_rate_limit_state()
        try:
            # Distinct clients behind the same edge must not exhaust each other.
            for i in range(5):
                response = client.get(
                    "/api/health", headers={"CF-Connecting-IP": f"198.51.100.{i}"}
                )
                assert response.status_code == 200
        finally:
            reset_rate_limit_state()
