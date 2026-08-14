"""Domain name analysis.

Combines syntax validation, structural heuristics and (optionally) passive DNS.
No connection is ever made to the domain's services.
"""

from __future__ import annotations

import math
from collections import Counter

from ..core.errors import ValidationFailure
from ..models.enums import AnalysisStatus, IndicatorType, Severity
from . import domain_utils as du
from .base import AnalyzerResult, Signal, ok, signal
from .dns_utils import resolve_hostname
from .patterns import IMPERSONATED_BRANDS, PHISHING_KEYWORDS, SUSPICIOUS_TLDS

CATEGORY = "domain"

# Shannon entropy above this on the second-level label is characteristic of
# algorithmically generated names (DGA) rather than human-chosen words.
DGA_ENTROPY_THRESHOLD = 3.6
DGA_MIN_LABEL_LENGTH = 10


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def analyze(raw_domain: str) -> AnalyzerResult:
    value = raw_domain.strip().rstrip(".").lower()
    if not value:
        raise ValidationFailure("A domain name is required.")
    if "/" in value or ":" in value or " " in value:
        raise ValidationFailure(
            "Submit a bare domain name (no scheme, path or port). Use the URL analyzer for full links."
        )
    if not du.is_valid_hostname(value):
        raise ValidationFailure(f"'{raw_domain}' is not a syntactically valid domain name.")

    ascii_host = du.to_ascii_host(value)
    parts = du.split_host(ascii_host)

    signals: list[Signal] = [
        ok("domain_valid", "Valid domain syntax",
           f"'{value}' conforms to hostname syntax rules (RFC 1123).", CATEGORY)
    ]
    details: dict = {
        "domain": ascii_host,
        "registrable_domain": parts.registrable_domain,
        "subdomain": parts.subdomain or None,
        "tld": parts.suffix,
        "label_count": len(parts.labels),
        "subdomain_depth": len(parts.subdomain_labels),
        "length": len(ascii_host),
    }

    signals.extend(_structure_signals(ascii_host, parts, details))
    signals.extend(_dns_signals(ascii_host, details))

    # Internal marker set by the DNS step; not part of the stored report body.
    status = details.pop("_status", AnalysisStatus.COMPLETED)

    return AnalyzerResult(
        indicator=ascii_host,
        indicator_display=ascii_host,
        indicator_type=IndicatorType.DOMAIN,
        signals=signals,
        details=details,
        status=status,
        lookup_key=ascii_host,
    )


def _structure_signals(host: str, parts: du.HostParts, details: dict) -> list[Signal]:
    out: list[Signal] = []

    if du.has_punycode(host):
        rendered = du.to_unicode_host(host)
        details["punycode_rendered_as"] = rendered
        out.append(
            signal(
                "domain_punycode",
                "Punycode (internationalised) domain",
                f"Encodes to '{rendered}'. Punycode is legitimate but is the standard "
                "mechanism for homograph lookalikes of well-known brands.",
                20,
                Severity.MEDIUM,
                CATEGORY,
                ("T1583.001", "T1036"),
            )
        )

    tld = parts.suffix.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        out.append(
            signal(
                "domain_suspicious_tld",
                f"High-abuse TLD (.{tld})",
                f"'.{tld}' registrations are cheap or free and show elevated abuse "
                "rates in public telemetry.",
                10,
                Severity.LOW,
                CATEGORY,
            )
        )

    depth = len(parts.subdomain_labels)
    if depth > 3:
        out.append(
            signal(
                "domain_excessive_subdomains",
                f"Excessive subdomain depth ({depth} labels)",
                "Nested labels push the registrable domain out of view in truncated "
                "address bars and mail clients.",
                12,
                Severity.MEDIUM,
                CATEGORY,
                ("T1036",),
            )
        )

    brand_hits = sorted(
        b for b in IMPERSONATED_BRANDS if b in parts.subdomain and b not in parts.registrable_domain
    )
    if brand_hits:
        details["impersonated_brands"] = brand_hits
        out.append(
            signal(
                "domain_brand_in_subdomain",
                f"Brand name in subdomain ({', '.join(brand_hits)})",
                f"'{brand_hits[0]}' appears in a subdomain of "
                f"'{parts.registrable_domain}', which the brand does not control.",
                25,
                Severity.HIGH,
                CATEGORY,
                ("T1566.002", "T1036"),
            )
        )

    keyword_hits = sorted(k for k in PHISHING_KEYWORDS if k in host)
    if keyword_hits:
        details["keywords"] = keyword_hits
        out.append(
            signal(
                "domain_phishing_keywords",
                f"Credential-themed keywords ({', '.join(keyword_hits[:4])})",
                "Security/authentication vocabulary inside a domain name is a common "
                "lure construction.",
                15,
                Severity.MEDIUM,
                CATEGORY,
                ("T1566.002",),
            )
        )

    sld = parts.registrable_domain.split(".")[0]
    entropy = round(shannon_entropy(sld), 3)
    details["second_level_label"] = sld
    details["second_level_entropy"] = entropy
    if len(sld) >= DGA_MIN_LABEL_LENGTH and entropy >= DGA_ENTROPY_THRESHOLD:
        out.append(
            signal(
                "domain_high_entropy",
                f"High-entropy label (H={entropy})",
                f"'{sld}' has a character distribution closer to random output than to "
                "natural language, consistent with a domain generation algorithm. "
                "Some legitimate CDN and hashing-based hostnames look the same.",
                15,
                Severity.MEDIUM,
                CATEGORY,
                ("T1583.001",),
            )
        )
    else:
        out.append(
            ok("domain_entropy_normal", "Label entropy within normal range",
               f"Second-level label '{sld}' (H={entropy}) resembles human-chosen text.",
               CATEGORY)
        )

    digit_ratio = sum(c.isdigit() for c in sld) / max(len(sld), 1)
    if digit_ratio > 0.4 and len(sld) > 5:
        out.append(
            signal(
                "domain_numeric_heavy",
                "Numeric-heavy domain label",
                "A high digit ratio in the registrable label is common in bulk-"
                "registered throwaway infrastructure.",
                8,
                Severity.LOW,
                CATEGORY,
            )
        )

    if sld.count("-") >= 3:
        out.append(
            signal(
                "domain_many_hyphens",
                f"Heavily hyphenated label ({sld.count('-')} hyphens)",
                "Long hyphenated names are used to pack keywords or brand names into "
                "a registrable domain.",
                8,
                Severity.LOW,
                CATEGORY,
            )
        )

    return out


def _dns_signals(host: str, details: dict) -> list[Signal]:
    out: list[Signal] = []
    dns = resolve_hostname(host)
    details["dns"] = {
        "attempted": dns.attempted,
        "resolved": dns.resolved,
        "addresses": dns.addresses,
        "error": dns.error,
    }

    if not dns.attempted:
        out.append(
            signal(
                "domain_dns_disabled",
                "Passive DNS lookup disabled",
                "ENABLE_DNS_LOOKUPS is off, so resolution data is not part of this "
                "assessment. Structural findings above are unaffected.",
                0,
                Severity.INFO,
                CATEGORY,
            )
        )
        return out

    if dns.resolved:
        out.append(
            ok("domain_resolves", f"Resolves to {len(dns.addresses)} address(es)",
               "Live A/AAAA records exist: " + ", ".join(dns.addresses[:5]), CATEGORY)
        )
    else:
        # An unresolvable domain is not proof of anything on its own; it is
        # equally consistent with a sinkholed campaign and with a typo.
        out.append(
            signal(
                "domain_no_resolution",
                "Domain does not currently resolve",
                dns.error or "No A/AAAA records returned. The domain may be parked, "
                "expired, sinkholed, or not yet activated (a known pre-campaign pattern).",
                8,
                Severity.LOW,
                CATEGORY,
            )
        )
        # The analysis itself succeeded; only the enrichment was inconclusive.
        details["_status"] = AnalysisStatus.PARTIAL
    return out
