"""Offline reputation engine.

This is the default provider and the only one enabled out of the box. It needs
no API key, no network, and no rate limit, which makes the platform fully
functional in an air-gapped lab -- a deliberate design goal.

Its dataset has exactly two kinds of entry:

1. **Real, public, harmless test artefacts** -- the EICAR anti-malware test
   file hashes. EICAR is an industry-standard, non-malicious 68-byte string
   published specifically so detection can be verified safely.
2. **Clearly-labelled synthetic entries** used for demos. Every synthetic
   record carries `synthetic: True` and says so in its detail text, so a
   screenshot of the UI can never be mistaken for real intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models.enums import ProviderResult
from .base import ProviderLookup, ThreatIntelProvider

SYNTHETIC_NOTE = "SYNTHETIC DEMO RECORD - not real threat intelligence."


@dataclass(frozen=True)
class LocalRecord:
    result: ProviderResult
    detail: str
    points: int
    synthetic: bool = True


# --- Hashes ---------------------------------------------------------------
_HASHES: dict[str, LocalRecord] = {
    # EICAR standard anti-malware test file. Real, public, and harmless: it is
    # a printable ASCII string that AV products agree to flag on sight.
    "44d88612fea8a8f36de82e1278abb02f": LocalRecord(
        ProviderResult.MALICIOUS,
        "EICAR standard anti-malware test file (MD5). Harmless industry test artefact, "
        "flagged by design to verify detection pipelines.",
        40,
        synthetic=False,
    ),
    "3395856ce81f2b7382dee72602f798b642f14140": LocalRecord(
        ProviderResult.MALICIOUS,
        "EICAR standard anti-malware test file (SHA-1). Harmless industry test artefact.",
        40,
        synthetic=False,
    ),
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": LocalRecord(
        ProviderResult.MALICIOUS,
        "EICAR standard anti-malware test file (SHA-256). Harmless industry test artefact.",
        40,
        synthetic=False,
    ),
    # Synthetic demo entries.
    "e1d4b7f0a2c39d68b5a41f0c7e2d9b3a6f8c1e5d0a7b4c2e9f3d6a8b1c5e7f0d": LocalRecord(
        ProviderResult.MALICIOUS,
        f"{SYNTHETIC_NOTE} Attributed to a fictional loader family 'DEMO/Trickle.A'.",
        40,
    ),
    "9f2b8c1d4e6a3f5b7c0d2e4a6b8c1d3e": LocalRecord(
        ProviderResult.SUSPICIOUS,
        f"{SYNTHETIC_NOTE} Low-confidence heuristic hit from a fictional sandbox feed.",
        20,
    ),
}

# --- Domains --------------------------------------------------------------
_DOMAINS: dict[str, LocalRecord] = {
    "secure-login-verify.example": LocalRecord(
        ProviderResult.MALICIOUS,
        f"{SYNTHETIC_NOTE} Fictional credential-phishing infrastructure.",
        35,
    ),
    "cdn-update-service.example": LocalRecord(
        ProviderResult.SUSPICIOUS,
        f"{SYNTHETIC_NOTE} Fictional malware staging host.",
        20,
    ),
    # RFC 2606 reserved names: safe to reference and can never be registered.
    "example.com": LocalRecord(
        ProviderResult.CLEAN,
        "IANA reserved documentation domain (RFC 2606). Cannot host live content.",
        0,
        synthetic=False,
    ),
    "example.org": LocalRecord(
        ProviderResult.CLEAN,
        "IANA reserved documentation domain (RFC 2606).",
        0,
        synthetic=False,
    ),
}

# --- IPs ------------------------------------------------------------------
_IPS: dict[str, LocalRecord] = {
    "203.0.113.66": LocalRecord(
        ProviderResult.MALICIOUS,
        f"{SYNTHETIC_NOTE} Fictional C2 node in TEST-NET-3 (RFC 5737) documentation space.",
        35,
    ),
    "198.51.100.23": LocalRecord(
        ProviderResult.SUSPICIOUS,
        f"{SYNTHETIC_NOTE} Fictional scanning source in TEST-NET-2 documentation space.",
        20,
    ),
    "8.8.8.8": LocalRecord(
        ProviderResult.CLEAN,
        "Google Public DNS resolver. Expected in normal network telemetry.",
        0,
        synthetic=False,
    ),
    "1.1.1.1": LocalRecord(
        ProviderResult.CLEAN,
        "Cloudflare public DNS resolver.",
        0,
        synthetic=False,
    ),
}


class LocalThreatIntelProvider(ThreatIntelProvider):
    name = "local"
    display_name = "Local Engine"

    def _wrap(self, record: LocalRecord | None, value: str, kind: str) -> ProviderLookup:
        if record is None:
            return ProviderLookup(
                provider=self.display_name,
                result=ProviderResult.UNKNOWN,
                detail=f"No local record for this {kind}. Absence of a record is not "
                "evidence of safety -- the offline dataset is intentionally small.",
            )
        return ProviderLookup(
            provider=self.display_name,
            result=record.result,
            detail=record.detail,
            score_contribution=record.points,
            raw={"indicator": value, "synthetic": record.synthetic},
        )

    async def lookup_hash(self, hash_value: str) -> ProviderLookup:
        return self._wrap(_HASHES.get(hash_value.lower().strip()), hash_value, "hash")

    async def lookup_domain(self, domain: str) -> ProviderLookup:
        return self._wrap(_DOMAINS.get(domain.lower().strip().rstrip(".")), domain, "domain")

    async def lookup_ip(self, ip: str) -> ProviderLookup:
        return self._wrap(_IPS.get(ip.strip()), ip, "IP address")

    async def lookup_url(self, url: str) -> ProviderLookup:
        # URLs are reduced to their host: the offline dataset tracks
        # infrastructure, not individual paths.
        from urllib.parse import urlparse

        host = (urlparse(url).hostname or url).lower()
        return self._wrap(_DOMAINS.get(host) or _IPS.get(host), host, "URL host")


def known_indicator_count() -> int:
    return len(_HASHES) + len(_DOMAINS) + len(_IPS)
