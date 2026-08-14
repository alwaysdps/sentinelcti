"""Provider registration and fan-out.

Adding a real provider is three steps: implement `ThreatIntelProvider`,
register the class here, and add its name to `ENABLED_PROVIDERS`. Nothing else
in the codebase needs to know it exists.
"""

from __future__ import annotations

import asyncio
import logging

from ..core.config import settings
from ..models.enums import IndicatorType
from .base import ProviderLookup, ThreatIntelProvider
from .local_provider import LocalThreatIntelProvider

logger = logging.getLogger("sentinelcti.providers")

_REGISTRY: dict[str, type[ThreatIntelProvider]] = {
    LocalThreatIntelProvider.name: LocalThreatIntelProvider,
    # Phase 2 slots -- classes land here, config decides whether they run.
    # VirusTotalProvider.name: VirusTotalProvider,
    # AbuseIPDBProvider.name: AbuseIPDBProvider,
}


def register(provider_cls: type[ThreatIntelProvider]) -> None:
    _REGISTRY[provider_cls.name] = provider_cls


def active_providers() -> list[ThreatIntelProvider]:
    providers: list[ThreatIntelProvider] = []
    for name in settings.provider_list:
        provider_cls = _REGISTRY.get(name)
        if provider_cls is None:
            logger.warning("Unknown provider '%s' in ENABLED_PROVIDERS; skipping.", name)
            continue
        instance = provider_cls()
        if not instance.is_configured:
            # Missing credentials are a configuration state, not an error: the
            # platform is designed to run with zero external providers.
            logger.info("Provider '%s' enabled but not configured; skipping.", name)
            continue
        providers.append(instance)
    return providers


async def lookup_all(indicator_type: IndicatorType, value: str | None) -> list[ProviderLookup]:
    """Query every active provider concurrently; never raises."""
    if not value:
        return []
    providers = active_providers()
    if not providers:
        return []
    results = await asyncio.gather(
        *(p.safe_lookup(indicator_type, value) for p in providers),
        return_exceptions=False,  # safe_lookup already absorbs failures
    )
    return list(results)


def provider_status() -> list[dict]:
    """Surfaced on the settings page so the operator can see what is live."""
    enabled = set(settings.provider_list)
    status = []
    for name, cls in _REGISTRY.items():
        instance = cls()
        status.append(
            {
                "name": name,
                "display_name": instance.display_name,
                "enabled": name in enabled,
                "configured": instance.is_configured,
                "requires_network": name != "local",
            }
        )
    return status
