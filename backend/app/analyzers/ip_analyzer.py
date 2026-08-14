"""IPv4 / IPv6 address analysis.

Classification is done entirely from the address itself using the IANA special-
purpose registries encoded in Python's `ipaddress` module, plus an optional PTR
lookup. No packets are sent to the address -- no ping, no port scan, no
connection. Scanning a third party's host is exactly the kind of active
behaviour this platform is designed not to do.
"""

from __future__ import annotations

import ipaddress

from ..core.errors import ValidationFailure
from ..models.enums import IndicatorType, Severity
from .base import AnalyzerResult, Signal, ok, signal
from .dns_utils import reverse_lookup

CATEGORY = "ip"

# Hosting/bulletproof-adjacent PTR fragments. Cloud hosting is entirely
# legitimate; the point is that a *server* PTR on an indicator that was
# expected to be a client is worth an analyst's attention.
HOSTING_PTR_HINTS = (
    "amazonaws", "digitalocean", "vultr", "linode", "ovh", "hetzner",
    "contabo", "azure", "googleusercontent", "scaleway", "hostwinds",
    "colocrossing", "choopa", "leaseweb", "serverion",
)

# Well-known public resolvers/anycast services: seeing these is normally noise,
# and calling that out prevents wasted triage time.
KNOWN_PUBLIC_SERVICES = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
}


def analyze(raw_ip: str) -> AnalyzerResult:
    value = raw_ip.strip().strip("[]")
    if not value:
        raise ValidationFailure("An IP address is required.")

    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationFailure(f"'{raw_ip}' is not a valid IPv4 or IPv6 address.") from exc

    signals: list[Signal] = [
        ok("ip_valid", f"Valid IPv{ip.version} address",
           f"'{ip}' parses as a well-formed IPv{ip.version} address.", CATEGORY)
    ]

    scope = _scope_of(ip)
    details: dict = {
        "address": str(ip),
        "version": ip.version,
        "scope": scope,
        "is_private": ip.is_private,
        "is_global": ip.is_global,
        "is_multicast": ip.is_multicast,
        "is_loopback": ip.is_loopback,
        "is_link_local": ip.is_link_local,
        "is_reserved": ip.is_reserved,
        "reverse_pointer": ip.reverse_pointer,
    }
    if ip.version == 4:
        details["integer_value"] = int(ip)

    signals.extend(_scope_signals(ip, scope, details))
    signals.extend(_ptr_signals(ip, details))

    return AnalyzerResult(
        indicator=str(ip),
        indicator_display=str(ip),
        indicator_type=IndicatorType.IP,
        signals=signals,
        details=details,
        lookup_key=str(ip),
    )


# RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges. Python's
# `is_private` lumps these in with RFC1918 space, but they mean something
# different to an analyst: an indicator in this space is almost certainly from
# a document, a lab, or a test dataset rather than from real telemetry.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _is_documentation(ip) -> bool:
    return any(ip.version == net.version and ip in net for net in DOCUMENTATION_NETWORKS)


def _scope_of(ip) -> str:
    if _is_documentation(ip):
        return "documentation"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if ip.is_reserved:
        return "reserved"
    return "public"


def _scope_signals(ip, scope: str, details: dict) -> list[Signal]:
    out: list[Signal] = []

    if scope == "public":
        out.append(
            ok("ip_public", "Globally routable address",
               "The address is in public unicast space and can be reached from the "
               "internet.", CATEGORY)
        )
        known = KNOWN_PUBLIC_SERVICES.get(str(ip))
        if known:
            details["known_service"] = known
            out.append(
                ok("ip_known_service", f"Known public service ({known})",
                   "This address belongs to a widely used public service and is "
                   "expected in most network telemetry.", CATEGORY)
            )
    elif scope == "documentation":
        out.append(
            signal(
                "ip_documentation_range",
                "Reserved documentation address",
                "This address is in IANA documentation space (RFC 5737 / RFC 3849). "
                "It is not routable and is reserved for examples and test data, so it "
                "cannot be live attacker infrastructure.",
                0,
                Severity.INFO,
                CATEGORY,
            )
        )
    else:
        # Non-routable addresses are frequently *reported* as IOCs by mistake;
        # saying so plainly is more useful than a score.
        out.append(
            signal(
                "ip_non_routable",
                f"Non-routable address ({scope})",
                f"{scope.capitalize()} space is not reachable across the public "
                "internet, so this address has no meaning as a standalone external "
                "indicator. It is only relevant with internal network context.",
                0,
                Severity.INFO,
                CATEGORY,
            )
        )

    if ip.version == 6 and getattr(ip, "ipv4_mapped", None):
        details["ipv4_mapped"] = str(ip.ipv4_mapped)
        out.append(
            signal(
                "ip_v4_mapped",
                "IPv4-mapped IPv6 address",
                f"Encodes IPv4 address {ip.ipv4_mapped}. Mapped forms are sometimes "
                "used to slip past allow/deny lists that only match IPv4 syntax.",
                10,
                Severity.LOW,
                CATEGORY,
                ("T1027",),
            )
        )

    if ip.version == 6 and getattr(ip, "teredo", None):
        details["teredo"] = True
        out.append(
            signal(
                "ip_teredo",
                "Teredo tunnelling address",
                "Teredo carries IPv6 over IPv4 UDP and is a known way to bypass "
                "IPv4-only egress filtering.",
                12,
                Severity.MEDIUM,
                CATEGORY,
                ("T1573",),
            )
        )

    return out


def _ptr_signals(ip, details: dict) -> list[Signal]:
    out: list[Signal] = []
    if not ip.is_global:
        # Reverse lookups on private space query the local resolver about
        # internal names; skip rather than leak internal topology into a report.
        details["ptr"] = {"attempted": False, "reason": "Skipped for non-global address."}
        return out

    ptr = reverse_lookup(str(ip))
    details["ptr"] = {
        "attempted": ptr.attempted,
        "resolved": ptr.resolved,
        "hostname": ptr.reverse_name,
        "error": ptr.error,
    }

    if not ptr.attempted:
        out.append(
            signal("ip_dns_disabled", "Reverse DNS disabled",
                   "ENABLE_DNS_LOOKUPS is off; PTR data is not part of this assessment.",
                   0, Severity.INFO, CATEGORY)
        )
        return out

    if ptr.resolved and ptr.reverse_name:
        name = ptr.reverse_name.lower()
        out.append(
            ok("ip_ptr_found", "PTR record present",
               f"Reverse DNS resolves to '{ptr.reverse_name}'.", CATEGORY)
        )
        hosting_hit = next((h for h in HOSTING_PTR_HINTS if h in name), None)
        if hosting_hit:
            details["hosting_provider_hint"] = hosting_hit
            out.append(
                signal(
                    "ip_hosting_ptr",
                    f"Hosting-provider PTR ({hosting_hit})",
                    "The address resolves to commodity hosting infrastructure, which is "
                    "where short-lived attacker infrastructure is most often rented. "
                    "This is context, not an accusation.",
                    5,
                    Severity.LOW,
                    CATEGORY,
                )
            )
    else:
        out.append(
            signal(
                "ip_no_ptr",
                "No PTR record",
                "Missing reverse DNS is common for dynamic and freshly-provisioned "
                "hosts. Well-run mail and web infrastructure usually has one.",
                5,
                Severity.LOW,
                CATEGORY,
            )
        )
    return out
