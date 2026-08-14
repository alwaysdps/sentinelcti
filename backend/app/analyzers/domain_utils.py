"""Hostname decomposition without an external public-suffix dependency.

A full Public Suffix List is ~9000 rules and would need periodic refreshing.
For MVP heuristics we only need to answer "where does the registrable domain
start", and a curated set of common multi-label suffixes answers that for the
overwhelming majority of real submissions. The limitation is documented in the
README rather than hidden -- an analyst reading `registrable_domain` should
know how it was derived.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Multi-label public suffixes we handle explicitly. Anything not listed is
# assumed to be a single-label suffix (".com", ".io", ...).
MULTI_LABEL_SUFFIXES: set[str] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "nhs.uk", "me.uk", "ltd.uk", "plc.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "go.kr",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.ec",
    "com.tr", "gov.tr", "edu.tr",
    "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn", "co.th", "co.id",
    "com.pk", "com.bd", "com.np", "com.lk",
    "com.eg", "com.sa", "com.ng", "com.gh", "com.ke",
    "com.ua", "com.pl", "net.pl", "org.pl", "com.ru", "net.ru", "org.ru",
    "com.es", "com.pt", "com.it", "com.de", "com.fr",
}

LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class HostParts:
    host: str
    subdomain: str
    registrable_domain: str
    suffix: str
    labels: list[str]

    @property
    def subdomain_labels(self) -> list[str]:
        return [label for label in self.subdomain.split(".") if label]


def split_host(host: str) -> HostParts:
    host = host.strip().rstrip(".").lower()
    labels = host.split(".")

    if len(labels) < 2:
        return HostParts(host=host, subdomain="", registrable_domain=host, suffix="", labels=labels)

    last_two = ".".join(labels[-2:])
    suffix_len = 2 if (last_two in MULTI_LABEL_SUFFIXES and len(labels) >= 3) else 1

    suffix = ".".join(labels[-suffix_len:])
    registrable = ".".join(labels[-(suffix_len + 1) :])
    subdomain = ".".join(labels[: -(suffix_len + 1)])
    return HostParts(
        host=host,
        subdomain=subdomain,
        registrable_domain=registrable,
        suffix=suffix,
        labels=labels,
    )


def is_valid_hostname(host: str) -> bool:
    """Syntactic RFC-1123 check. Accepts IDN in either A-label or U-label form."""
    if not host or len(host) > 253:
        return False
    candidate = host.rstrip(".")
    try:
        # IDNA encoding both validates and normalises internationalised names.
        candidate = candidate.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return False
    labels = candidate.split(".")
    if len(labels) < 2:
        return False
    if not all(LABEL_RE.match(label) for label in labels):
        return False
    # A purely numeric last label means this is an IP address, not a hostname.
    return not labels[-1].isdigit()


def has_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.lower().split("."))


def contains_non_ascii(value: str) -> bool:
    return any(ord(ch) > 127 for ch in value)


def to_ascii_host(host: str) -> str:
    """Best-effort A-label form; returns the input unchanged if not encodable."""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return host


def to_unicode_host(host: str) -> str:
    """U-label form, so the report can show what a punycode name renders as."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return host
