"""URL analyzer behaviour."""

from __future__ import annotations

import pytest

from app.analyzers import url_analyzer
from app.core.errors import ValidationFailure
from app.models.enums import IndicatorType, Severity


def codes(result) -> set[str]:
    return {s.code for s in result.signals}


class TestValidation:
    def test_valid_https_url_is_accepted(self):
        result = url_analyzer.analyze("https://example.com/products")
        assert result.indicator_type is IndicatorType.URL
        assert result.details["scheme"] == "https"
        assert result.details["host"] == "example.com"

    def test_missing_scheme_is_assumed_http_and_recorded(self):
        result = url_analyzer.analyze("example.com/login")
        assert result.details["assumed_scheme"] is True
        assert result.details["normalised_url"].startswith("http://")

    @pytest.mark.parametrize("bad", ["", "   ", "http://", "https://", "://nope"])
    def test_structurally_invalid_urls_are_rejected(self, bad):
        with pytest.raises(ValidationFailure):
            url_analyzer.analyze(bad)

    def test_non_web_scheme_is_rejected(self):
        with pytest.raises(ValidationFailure) as exc:
            url_analyzer.analyze("ftp://files.example.com/payload.bin")
        assert "scheme" in str(exc.value).lower()

    def test_invalid_hostname_is_rejected(self):
        with pytest.raises(ValidationFailure):
            url_analyzer.analyze("http://not_a_host!!/")

    def test_overlong_url_is_rejected(self):
        with pytest.raises(ValidationFailure):
            url_analyzer.analyze("https://example.com/" + "a" * 2100)


class TestTransport:
    def test_https_produces_a_zero_point_pass_finding(self):
        result = url_analyzer.analyze("https://example.com/")
        https = next(s for s in result.signals if s.code == "url_https")
        assert https.points == 0
        assert https.severity is Severity.PASS

    def test_plaintext_http_is_scored(self):
        result = url_analyzer.analyze("http://example.com/")
        http = next(s for s in result.signals if s.code == "url_plaintext_http")
        assert http.points > 0

    def test_non_standard_port_is_flagged(self):
        result = url_analyzer.analyze("http://example.com:8081/gate.php")
        assert "url_nonstandard_port" in codes(result)


class TestHostHeuristics:
    def test_ip_literal_host_is_flagged(self):
        result = url_analyzer.analyze("http://198.51.100.23/login")
        assert "url_ip_host" in codes(result)
        assert result.details["host_is_ip_literal"] is True

    def test_ipv6_literal_host_is_recognised(self):
        result = url_analyzer.analyze("http://[2001:db8::1]/admin")
        assert result.details["host_is_ip_literal"] is True
        assert result.details["ip_version"] == 6

    def test_punycode_host_is_flagged_and_rendered(self):
        result = url_analyzer.analyze("https://xn--pypal-4ve.example/signin")
        assert "url_punycode" in codes(result)
        assert "punycode_rendered_as" in result.details

    def test_excessive_subdomain_depth_is_flagged(self):
        result = url_analyzer.analyze("http://a.b.c.d.e.example.com/")
        assert "url_excessive_subdomains" in codes(result)
        assert result.details["subdomain_depth"] >= 4

    def test_brand_in_subdomain_is_high_severity(self):
        result = url_analyzer.analyze("http://paypal.secure.attacker-domain.example/login")
        brand = next(s for s in result.signals if s.code == "url_brand_in_subdomain")
        assert brand.severity is Severity.HIGH
        assert brand.points >= 20

    def test_brand_owning_its_own_domain_is_not_flagged(self):
        result = url_analyzer.analyze("https://www.paypal.com/signin")
        assert "url_brand_in_subdomain" not in codes(result)

    def test_suspicious_tld_is_flagged(self):
        result = url_analyzer.analyze("https://download-now.xyz/")
        assert "url_suspicious_tld" in codes(result)

    def test_registrable_domain_handles_multi_label_suffix(self):
        result = url_analyzer.analyze("https://shop.example.co.uk/")
        assert result.details["registrable_domain"] == "example.co.uk"
        assert result.details["subdomain"] == "shop"


class TestStructuralHeuristics:
    def test_embedded_credentials_are_flagged(self):
        result = url_analyzer.analyze("http://paypal.com:pass@evil.example/")
        assert "url_embedded_credentials" in codes(result)

    def test_nested_url_in_query_is_flagged(self):
        result = url_analyzer.analyze("https://example.com/r?next=https://evil.example/x")
        assert "url_nested_url" in codes(result)

    def test_excessive_length_is_flagged(self):
        result = url_analyzer.analyze("https://example.com/" + "segment/" * 30)
        assert "url_excessive_length" in codes(result)

    def test_heavy_percent_encoding_is_flagged(self):
        result = url_analyzer.analyze("https://example.com/%61%62%63%64%65%66%67")
        assert "url_heavy_encoding" in codes(result)

    def test_backslash_is_treated_as_suspicious(self):
        result = url_analyzer.analyze("https://example.com/path\\..\\admin")
        assert "url_suspicious_chars" in codes(result)


class TestPayloadHeuristics:
    def test_direct_executable_link_is_flagged(self):
        result = url_analyzer.analyze("https://example.com/files/setup.exe")
        assert "url_executable_payload" in codes(result)

    def test_double_extension_is_flagged(self):
        result = url_analyzer.analyze("https://example.com/invoice.pdf.exe")
        assert "url_double_extension" in codes(result)

    def test_credential_path_keywords_are_flagged(self):
        result = url_analyzer.analyze("https://example.com/account/verify/login")
        assert "url_phishing_keywords_path" in codes(result)


class TestOverallShape:
    def test_benign_url_produces_only_pass_findings(self):
        result = url_analyzer.analyze("https://example.com/about")
        assert sum(s.points for s in result.signals) == 0

    def test_phishing_url_accumulates_multiple_scored_signals(self):
        result = url_analyzer.analyze(
            "http://paypal.secure.login.account-verify.xyz/webscr/confirm.php?data=" + "A" * 120
        )
        scored = [s for s in result.signals if s.points > 0]
        assert len(scored) >= 4
        assert sum(s.points for s in scored) >= 50

    def test_lookup_key_is_the_host(self):
        result = url_analyzer.analyze("https://sub.example.com/path")
        assert result.lookup_key == "sub.example.com"
