"""IP and domain analyzer behaviour.

DNS is disabled for the whole test session (see conftest), so these assertions
depend only on the address/name itself -- deterministic and offline.
"""

from __future__ import annotations

import pytest

from app.analyzers import domain_analyzer, ip_analyzer
from app.core.errors import ValidationFailure
from app.models.enums import IndicatorType


def codes(result) -> set[str]:
    return {s.code for s in result.signals}


class TestIPValidation:
    @pytest.mark.parametrize("value", ["8.8.8.8", "203.0.113.66", "2001:db8::1", "::1"])
    def test_valid_addresses_are_accepted(self, value):
        result = ip_analyzer.analyze(value)
        assert result.indicator_type is IndicatorType.IP

    @pytest.mark.parametrize("bad", ["", "999.1.1.1", "1.2.3", "example.com", "1.2.3.4.5", "not-an-ip"])
    def test_invalid_addresses_are_rejected(self, bad):
        with pytest.raises(ValidationFailure):
            ip_analyzer.analyze(bad)

    def test_bracketed_ipv6_is_accepted(self):
        assert ip_analyzer.analyze("[2001:db8::1]").indicator == "2001:db8::1"


class TestIPClassification:
    def test_public_address_is_classified_as_global(self):
        result = ip_analyzer.analyze("8.8.8.8")
        assert result.details["scope"] == "public"
        assert result.details["is_global"] is True

    def test_documentation_range_is_named_rather_than_lumped_with_rfc1918(self):
        # Python's ipaddress reports TEST-NET as "private"; for an analyst the
        # distinction between internal space and doc space matters.
        result = ip_analyzer.analyze("203.0.113.66")
        assert result.details["scope"] == "documentation"
        assert "ip_documentation_range" in codes(result)

    @pytest.mark.parametrize(
        ("value", "scope"),
        [("10.0.0.5", "private"), ("192.168.1.1", "private"),
         ("127.0.0.1", "loopback"), ("169.254.1.1", "link-local"), ("224.0.0.1", "multicast")],
    )
    def test_special_purpose_ranges_are_identified(self, value, scope):
        result = ip_analyzer.analyze(value)
        assert result.details["scope"] == scope
        assert "ip_non_routable" in codes(result)

    def test_non_routable_addresses_add_no_points(self):
        result = ip_analyzer.analyze("192.168.1.1")
        assert sum(s.points for s in result.signals) == 0

    def test_ipv4_mapped_ipv6_is_flagged(self):
        result = ip_analyzer.analyze("::ffff:203.0.113.66")
        assert "ip_v4_mapped" in codes(result)

    def test_known_public_resolver_is_annotated(self):
        result = ip_analyzer.analyze("8.8.8.8")
        assert "ip_known_service" in codes(result)

    def test_reverse_lookup_is_skipped_for_private_space(self):
        result = ip_analyzer.analyze("10.1.2.3")
        assert result.details["ptr"]["attempted"] is False


class TestDomainValidation:
    @pytest.mark.parametrize("value", ["example.com", "sub.example.co.uk", "xn--pypal-4ve.example"])
    def test_valid_domains_are_accepted(self, value):
        result = domain_analyzer.analyze(value)
        assert result.indicator_type is IndicatorType.DOMAIN

    @pytest.mark.parametrize(
        "bad",
        ["", "   ", "no-tld", "bad_underscore.com", "-leading.example.com",
         "http://example.com", "example.com/path", "example.com:8080"],
    )
    def test_invalid_domains_are_rejected(self, bad):
        with pytest.raises(ValidationFailure):
            domain_analyzer.analyze(bad)

    def test_trailing_dot_and_case_are_normalised(self):
        assert domain_analyzer.analyze("Example.COM.").indicator == "example.com"


class TestDomainHeuristics:
    def test_multi_label_suffix_is_handled(self):
        result = domain_analyzer.analyze("shop.example.co.uk")
        assert result.details["registrable_domain"] == "example.co.uk"

    def test_punycode_is_flagged_and_rendered(self):
        result = domain_analyzer.analyze("xn--pypal-4ve.example")
        assert "domain_punycode" in codes(result)
        assert result.details["punycode_rendered_as"] != "xn--pypal-4ve.example"

    def test_dga_like_label_is_flagged_by_entropy(self):
        result = domain_analyzer.analyze("a7f3k9x2m8q4v1z6.example.com")
        # The high-entropy label is the *subdomain* here, so check the
        # registrable label case explicitly instead.
        result = domain_analyzer.analyze("x7k2m9q4v1z6b3n8.com")
        assert "domain_high_entropy" in codes(result)

    def test_ordinary_word_domain_is_not_flagged_as_dga(self):
        result = domain_analyzer.analyze("northwindtraders.com")
        assert "domain_entropy_normal" in codes(result)

    def test_brand_in_subdomain_is_flagged(self):
        result = domain_analyzer.analyze("paypal.secure.attacker.example")
        assert "domain_brand_in_subdomain" in codes(result)

    def test_suspicious_tld_is_flagged(self):
        assert "domain_suspicious_tld" in codes(domain_analyzer.analyze("freestuff.xyz"))

    def test_benign_domain_scores_zero(self):
        result = domain_analyzer.analyze("example.com")
        assert sum(s.points for s in result.signals) == 0

    def test_dns_disabled_is_reported_rather_than_silently_skipped(self):
        result = domain_analyzer.analyze("example.com")
        assert "domain_dns_disabled" in codes(result)
        assert result.details["dns"]["attempted"] is False


class TestEntropyHelper:
    def test_uniform_string_has_zero_entropy(self):
        assert domain_analyzer.shannon_entropy("aaaaaa") == 0.0

    def test_empty_string_is_safe(self):
        assert domain_analyzer.shannon_entropy("") == 0.0

    def test_varied_string_has_higher_entropy(self):
        assert domain_analyzer.shannon_entropy("abcdefgh") > domain_analyzer.shannon_entropy("aaaaaaab")
