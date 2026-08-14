"""Threat-intelligence provider interface.

The contract exists so that adding VirusTotal, AbuseIPDB, or an internal MISP
instance later is a matter of writing one class and adding a name to
`ENABLED_PROVIDERS` -- no analyzer, service or route changes.

Two rules every implementation must honour:

* **Never mandatory.** A provider that is slow, rate-limited, or down must
  degrade the analysis to PARTIAL, never fail it. `safe_lookup` enforces this.
* **Never a secret holder.** Credentials come from settings (environment), so
  no key is ever written into source.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..models.enums import IndicatorType, ProviderResult

logger = logging.getLogger("sentinelcti.providers")

DEFAULT_TIMEOUT_SECONDS = 6.0


@dataclass
class ProviderLookup:
    provider: str
    result: ProviderResult
    detail: str
    # Points this provider contributes if the risk engine consumes it.
    score_contribution: int = 0
    reference_url: str | None = None
    raw: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "result": self.result.value,
            "detail": self.detail,
            "score_contribution": self.score_contribution,
            "reference_url": self.reference_url,
        }


class ThreatIntelProvider(ABC):
    """Base class for reputation sources."""

    name: str = "provider"
    display_name: str = "Provider"

    @property
    def is_configured(self) -> bool:
        """Whether the provider has what it needs (API key, endpoint, ...)."""
        return True

    @abstractmethod
    async def lookup_hash(self, hash_value: str) -> ProviderLookup: ...

    async def lookup_domain(self, domain: str) -> ProviderLookup:
        return self.unsupported(domain, "domain")

    async def lookup_ip(self, ip: str) -> ProviderLookup:
        return self.unsupported(ip, "IP")

    async def lookup_url(self, url: str) -> ProviderLookup:
        return self.unsupported(url, "URL")

    def unsupported(self, _value: str, kind: str) -> ProviderLookup:
        return ProviderLookup(
            provider=self.display_name,
            result=ProviderResult.UNKNOWN,
            detail=f"This provider does not support {kind} lookups.",
        )

    async def lookup(self, indicator_type: IndicatorType, value: str) -> ProviderLookup:
        dispatch = {
            IndicatorType.HASH: self.lookup_hash,
            IndicatorType.FILE: self.lookup_hash,  # files are looked up by SHA-256
            IndicatorType.DOMAIN: self.lookup_domain,
            IndicatorType.IP: self.lookup_ip,
            IndicatorType.URL: self.lookup_url,
        }
        return await dispatch[indicator_type](value)

    async def safe_lookup(
        self, indicator_type: IndicatorType, value: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
    ) -> ProviderLookup:
        """Run a lookup that cannot break the surrounding analysis.

        Timeouts and exceptions are converted into an ERROR result. The report
        then shows the provider as unavailable, which is honest, instead of the
        whole submission failing because a third party had a bad day.
        """
        try:
            return await asyncio.wait_for(self.lookup(indicator_type, value), timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning("provider=%s timed out after %ss", self.name, timeout)
            return ProviderLookup(
                provider=self.display_name,
                result=ProviderResult.ERROR,
                detail=f"Lookup timed out after {timeout:g}s; treated as no data.",
            )
        except Exception as exc:  # noqa: BLE001 - provider isolation is the point
            logger.warning("provider=%s failed: %s", self.name, exc)
            return ProviderLookup(
                provider=self.display_name,
                result=ProviderResult.ERROR,
                detail="Provider unavailable; this analysis proceeded without it.",
            )
