"""Static URL analysis.

Deliberately passive: the URL is *parsed*, never fetched. Requesting a
suspected phishing or malware-delivery URL from the analyst's network leaks
that the campaign is being investigated, can burn a sample, and in the worst
case pulls hostile content onto the analysis host. Active fetching stays behind
`ENABLE_ACTIVE_URL_FETCH`, which the MVP never turns on for the user.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import parse_qs, unquote, urlparse

from ..core.errors import ValidationFailure
from ..models.enums import IndicatorType, Severity
from . import domain_utils as du
from .base import AnalyzerResult, Signal, ok, signal
from .patterns import (
    ARCHIVE_EXTENSIONS,
    DOUBLE_EXTENSION_RE,
    IMPERSONATED_BRANDS,
    PHISHING_KEYWORDS,
    RISKY_FILE_EXTENSIONS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

CATEGORY = "url"

MAX_REASONABLE_URL_LENGTH = 100
EXCESSIVE_URL_LENGTH = 200
MAX_REASONABLE_SUBDOMAIN_LABELS = 3
STANDARD_PORTS = {80, 443, 8080, 8443}


def _normalise(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValidationFailure("A URL is required.")
    if len(value) > 2048:
        raise ValidationFailure("URL exceeds the maximum supported length of 2048 characters.")
    # A bare "example.com/path" is what users paste most often. Assume http so
    # that the missing-scheme case is *analysed* (and flagged) rather than
    # rejected -- but record that we had to assume.
    if "://" not in value:
        value = f"http://{value}"
    return value


def analyze(raw_url: str) -> AnalyzerResult:
    original = raw_url.strip()
    url = _normalise(raw_url)

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        # urlparse raises on an unbalanced '[' or ']' in the authority, which it
        # tries to read as an IPv6 literal. Left unhandled that turns malformed
        # user input into a 500 -- submitted input must always produce a
        # validation error, never a server error.
        raise ValidationFailure(f"URL could not be parsed: {exc}.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValidationFailure(
            f"Unsupported URL scheme '{parsed.scheme}'. Only http and https are analysed."
        )

    host = (parsed.hostname or "").strip()
    if not host:
        raise ValidationFailure("URL does not contain a host component.")

    signals: list[Signal] = []
    details: dict = {
        "original_input": original,
        "normalised_url": url,
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "url_length": len(url),
        "assumed_scheme": "://" not in original,
    }

    host_is_ip, ip_obj = _classify_host_as_ip(host)
    details["host_is_ip_literal"] = host_is_ip

    if host_is_ip:
        signals.extend(_ip_host_signals(ip_obj, details))
    else:
        signals.extend(_hostname_signals(host, details))

    signals.extend(_scheme_signals(parsed, details))
    signals.extend(_structure_signals(url, parsed, details))
    signals.extend(_path_signals(parsed, details))

    display = url if len(url) <= 120 else url[:117] + "..."
    return AnalyzerResult(
        indicator=url,
        indicator_display=display,
        indicator_type=IndicatorType.URL,
        signals=signals,
        details=details,
        lookup_key=host,
    )


# --------------------------------------------------------------------------
# Host handling
# --------------------------------------------------------------------------
def _classify_host_as_ip(host: str) -> tuple[bool, ipaddress._BaseAddress | None]:
    candidate = host.strip("[]")  # IPv6 literals arrive bracketed
    try:
        return True, ipaddress.ip_address(candidate)
    except ValueError:
        return False, None


def _ip_host_signals(ip_obj, details: dict) -> list[Signal]:
    out = [
        signal(
            "url_ip_host",
            "IP address used instead of a domain name",
            "The URL addresses a raw IP literal. Legitimate services publish a "
            "hostname; direct IP links are common in phishing kits and malware "
            "staging URLs because they need no domain registration.",
            15,
            Severity.MEDIUM,
            CATEGORY,
            ("T1071.001",),
        )
    ]
    details["ip_version"] = ip_obj.version
    details["ip_is_private"] = ip_obj.is_private
    if ip_obj.is_private or ip_obj.is_loopback:
        out.append(
            signal(
                "url_private_ip_host",
                "Host is a private/loopback address",
                "The target is not routable from the public internet. In a phishing "
                "context this often indicates an internal pivot or a broken lure.",
                5,
                Severity.LOW,
                CATEGORY,
            )
        )
    return out


def _hostname_signals(host: str, details: dict) -> list[Signal]:
    out: list[Signal] = []

    if not du.is_valid_hostname(host):
        raise ValidationFailure(f"'{host}' is not a syntactically valid hostname.")

    ascii_host = du.to_ascii_host(host)
    parts = du.split_host(ascii_host)
    details.update(
        {
            "registrable_domain": parts.registrable_domain,
            "subdomain": parts.subdomain,
            "tld": parts.suffix,
            "subdomain_depth": len(parts.subdomain_labels),
        }
    )

    out.append(ok("url_valid_host", "Valid hostname syntax",
                  f"'{host}' parses as a well-formed hostname.", CATEGORY))

    if du.has_punycode(ascii_host):
        rendered = du.to_unicode_host(ascii_host)
        details["punycode_rendered_as"] = rendered
        out.append(
            signal(
                "url_punycode",
                "Punycode (internationalised) domain",
                f"The host uses punycode encoding and renders as '{rendered}'. "
                "Punycode is legitimate, but it is also the standard vehicle for "
                "homograph attacks where a lookalike renders like a known brand.",
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
                "url_suspicious_tld",
                f"High-abuse TLD (.{tld})",
                f"'.{tld}' has a historically elevated abuse ratio and low/zero "
                "registration cost. This is a prior, not a verdict.",
                10,
                Severity.LOW,
                CATEGORY,
            )
        )

    if parts.registrable_domain in URL_SHORTENERS:
        out.append(
            signal(
                "url_shortener",
                "URL shortening service",
                f"'{parts.registrable_domain}' hides the real destination behind a "
                "redirect. The final target cannot be assessed without resolving it.",
                12,
                Severity.MEDIUM,
                CATEGORY,
            )
        )

    depth = len(parts.subdomain_labels)
    if depth > MAX_REASONABLE_SUBDOMAIN_LABELS:
        out.append(
            signal(
                "url_excessive_subdomains",
                f"Excessive subdomain depth ({depth} labels)",
                "Deeply nested subdomains are used to push the real registrable "
                "domain out of view in browser address bars, especially on mobile.",
                12,
                Severity.MEDIUM,
                CATEGORY,
                ("T1036",),
            )
        )

    # Brand name in a subdomain the brand does not own is the single most
    # reliable static phishing tell we can compute without network access.
    brand_hits = sorted(
        b for b in IMPERSONATED_BRANDS if b in parts.subdomain and b not in parts.registrable_domain
    )
    if brand_hits:
        details["impersonated_brands"] = brand_hits
        out.append(
            signal(
                "url_brand_in_subdomain",
                f"Brand name in subdomain ({', '.join(brand_hits)})",
                f"The host places '{brand_hits[0]}' in a subdomain of "
                f"'{parts.registrable_domain}', which is not owned by that brand. "
                "This is a classic credential-phishing construction.",
                25,
                Severity.HIGH,
                CATEGORY,
                ("T1566.002", "T1036"),
            )
        )

    keyword_hits = sorted(k for k in PHISHING_KEYWORDS if k in ascii_host)
    if keyword_hits:
        details["host_keywords"] = keyword_hits
        out.append(
            signal(
                "url_phishing_keywords_host",
                f"Credential-themed keywords in host ({', '.join(keyword_hits[:4])})",
                "Words like 'login', 'verify' or 'secure' inside the hostname are a "
                "common lure pattern; genuine services do not need them there.",
                15,
                Severity.MEDIUM,
                CATEGORY,
                ("T1566.002",),
            )
        )

    if "-" in parts.registrable_domain.split(".")[0] and any(
        b in parts.registrable_domain for b in IMPERSONATED_BRANDS
    ):
        out.append(
            signal(
                "url_hyphenated_brand",
                "Hyphenated brand-lookalike domain",
                f"'{parts.registrable_domain}' combines a known brand with hyphenated "
                "filler, a common way to register a plausible-looking lookalike.",
                18,
                Severity.MEDIUM,
                CATEGORY,
                ("T1583.001", "T1036"),
            )
        )

    return out


# --------------------------------------------------------------------------
# Scheme / transport
# --------------------------------------------------------------------------
def _scheme_signals(parsed, details: dict) -> list[Signal]:
    out: list[Signal] = []
    if parsed.scheme.lower() == "https":
        out.append(
            ok("url_https", "HTTPS in use",
               "Transport is encrypted. Note that certificate validity says nothing "
               "about intent -- most phishing sites now use valid TLS.", CATEGORY)
        )
    else:
        out.append(
            signal(
                "url_plaintext_http",
                "Plaintext HTTP",
                "Credentials or data submitted to this URL travel unencrypted and are "
                "readable by anyone on the path.",
                10,
                Severity.LOW,
                CATEGORY,
            )
        )

    port = parsed.port
    if port is not None and port not in STANDARD_PORTS:
        details["non_standard_port"] = port
        out.append(
            signal(
                "url_nonstandard_port",
                f"Non-standard port ({port})",
                "Web content served on an unusual port often indicates ad-hoc "
                "infrastructure such as a staging or C2 listener.",
                10,
                Severity.LOW,
                CATEGORY,
            )
        )

    if parsed.username or parsed.password:
        details["embedded_credentials"] = True
        out.append(
            signal(
                "url_embedded_credentials",
                "Credentials embedded in URL",
                "A 'user:pass@host' URL is frequently used to make the text before "
                "the '@' look like the real destination while the browser navigates "
                "to whatever follows it.",
                25,
                Severity.HIGH,
                CATEGORY,
                ("T1566.002", "T1036"),
            )
        )
    return out


# --------------------------------------------------------------------------
# Structure / encoding
# --------------------------------------------------------------------------
def _structure_signals(url: str, parsed, details: dict) -> list[Signal]:
    out: list[Signal] = []
    length = len(url)

    if length > EXCESSIVE_URL_LENGTH:
        out.append(
            signal(
                "url_excessive_length",
                f"Excessive URL length ({length} characters)",
                "Very long URLs are used to bury the true destination and to carry "
                "encoded payloads or tracking identifiers.",
                12,
                Severity.MEDIUM,
                CATEGORY,
            )
        )
    elif length > MAX_REASONABLE_URL_LENGTH:
        out.append(
            signal(
                "url_long",
                f"Above-average URL length ({length} characters)",
                "Longer than a typical link, which slightly raises the chance the "
                "destination is being obscured.",
                5,
                Severity.LOW,
                CATEGORY,
            )
        )

    decoded = unquote(url)
    encoded_count = url.count("%")
    details["percent_encoded_sequences"] = encoded_count
    if encoded_count >= 6 or (decoded != url and encoded_count >= 3):
        out.append(
            signal(
                "url_heavy_encoding",
                f"Heavy percent-encoding ({encoded_count} sequences)",
                "Repeated percent-encoding is used to defeat naive string matching in "
                "mail and proxy filters.",
                12,
                Severity.MEDIUM,
                CATEGORY,
                ("T1027",),
            )
        )

    # A second scheme inside the path/query usually means an open redirect or a
    # nested payload URL.
    remainder = f"{parsed.path}?{parsed.query}"
    if "http://" in remainder.lower() or "https://" in remainder.lower():
        details["nested_url_detected"] = True
        out.append(
            signal(
                "url_nested_url",
                "Second URL embedded in path or query",
                "The link carries another URL as a parameter -- the signature of an "
                "open-redirect abuse chain that borrows a trusted domain's reputation.",
                18,
                Severity.MEDIUM,
                CATEGORY,
                ("T1566.002",),
            )
        )

    if "@" in url.split("://", 1)[1].split("/", 1)[0] and not (parsed.username or parsed.password):
        out.append(
            signal(
                "url_at_symbol_authority",
                "'@' present in URL authority",
                "Everything before '@' is discarded by the browser; this is used to "
                "make a hostile host look like a familiar one.",
                20,
                Severity.HIGH,
                CATEGORY,
                ("T1036",),
            )
        )

    for ch in ("\\", "\t", "\n", "\r", "\x00"):
        if ch in url:
            details["control_or_backslash_chars"] = True
            out.append(
                signal(
                    "url_suspicious_chars",
                    "Suspicious control characters in URL",
                    "Backslashes and control characters are parsed inconsistently "
                    "across browsers and are used to smuggle a different destination.",
                    15,
                    Severity.MEDIUM,
                    CATEGORY,
                    ("T1027",),
                )
            )
            break

    params = parse_qs(parsed.query)
    details["query_parameter_count"] = len(params)
    if len(params) > 8:
        out.append(
            signal(
                "url_many_params",
                f"Unusually many query parameters ({len(params)})",
                "A large parameter set can indicate victim tracking or data exfil "
                "encoded into the request.",
                5,
                Severity.LOW,
                CATEGORY,
            )
        )
    return out


# --------------------------------------------------------------------------
# Path inspection
# --------------------------------------------------------------------------
def _path_signals(parsed, details: dict) -> list[Signal]:
    out: list[Signal] = []
    path = parsed.path or ""
    last_segment = path.rsplit("/", 1)[-1].lower()
    extension = last_segment.rsplit(".", 1)[-1] if "." in last_segment else ""
    details["path_filename"] = last_segment or None
    details["path_extension"] = extension or None

    if extension in RISKY_FILE_EXTENSIONS:
        out.append(
            signal(
                "url_executable_payload",
                f"Directly-linked executable content (.{extension})",
                "The URL points straight at an executable or script file rather than a "
                "page, which is how drive-by and lure downloads are delivered.",
                20,
                Severity.HIGH,
                CATEGORY,
                ("T1105", "T1204.002"),
            )
        )
    elif extension in ARCHIVE_EXTENSIONS:
        out.append(
            signal(
                "url_archive_payload",
                f"Directly-linked archive (.{extension})",
                "Archives are used to wrap executable payloads past content filters.",
                10,
                Severity.LOW,
                CATEGORY,
                ("T1105",),
            )
        )

    if DOUBLE_EXTENSION_RE.search(last_segment):
        out.append(
            signal(
                "url_double_extension",
                "Double file extension in path",
                f"'{last_segment}' presents as a document but ends in an executable "
                "extension -- a masquerading technique aimed at users whose file "
                "manager hides known extensions.",
                20,
                Severity.HIGH,
                CATEGORY,
                ("T1036", "T1204.002"),
            )
        )

    keyword_hits = sorted(k for k in PHISHING_KEYWORDS if k in path.lower())
    if keyword_hits:
        details["path_keywords"] = keyword_hits
        out.append(
            signal(
                "url_phishing_keywords_path",
                f"Credential-themed path segments ({', '.join(keyword_hits[:4])})",
                "The path advertises a login/verification flow, consistent with a "
                "credential-harvesting page.",
                10,
                Severity.LOW,
                CATEGORY,
                ("T1566.002",),
            )
        )
    return out
