"""Health, dashboard statistics and platform configuration."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..core import access, cloudflare
from ..core.owner import resolve_owner_key
from ..core.config import settings
from ..database import get_db
from ..database.session import backend_name
from ..models.analysis import Analysis
from ..providers import registry
from ..schemas.analysis import (
    AccessStatus,
    EdgeStatus,
    AnalysisSummary,
    DashboardStats,
    HealthResponse,
    PlatformConfig,
)
from ..services import query_service
from ..services.risk_engine import bands_reference

router = APIRouter(prefix="/api", tags=["System"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health",
    description="Liveness plus a real database round-trip and the provider roster.",
)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    # A health check that does not touch the database is not a health check.
    # `connected` is tracked as a boolean rather than inferred from the display
    # string, so enriching that string can never silently flip the status.
    try:
        db.execute(text("SELECT 1"))
        stored = db.execute(select(func.count()).select_from(Analysis)).scalar_one()
        connected = True
        db_state = f"connected ({backend_name()})"
    except Exception as exc:  # noqa: BLE001 - report degradation instead of 500ing
        stored = -1
        connected = False
        # The exception *type* only: enough to tell a missing driver
        # (ModuleNotFoundError) from a refused connection (OperationalError)
        # from a missing table (ProgrammingError), which is the whole question
        # when a deployment will not talk to its database. The message is
        # omitted deliberately -- it can contain the connection string.
        db_state = f"unavailable ({type(exc).__name__})"

    return HealthResponse(
        status="ok" if connected else "degraded",
        version=settings.app_version,
        environment=settings.environment,
        database=db_state,
        providers=registry.provider_status(),
        analyses_stored=stored,
    )


@router.get(
    "/stats/dashboard",
    response_model=DashboardStats,
    summary="Dashboard statistics",
    description=(
        "Every figure is aggregated from the database on each request. Nothing on "
        "the dashboard is hard-coded or cached."
    ),
)
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    activity_days: int = Query(30, ge=7, le=90, description="Length of the activity series."),
) -> DashboardStats:
    stats = query_service.dashboard_stats(
        db, owner_key=resolve_owner_key(request), activity_days=activity_days
    )
    stats["recent"] = [AnalysisSummary.model_validate(r, from_attributes=True) for r in stats["recent"]]
    return DashboardStats(**stats)


@router.get(
    "/config",
    response_model=PlatformConfig,
    summary="Platform capabilities",
    description=(
        "Read-only view of how this instance is configured, used by the Settings "
        "page. Reports **whether** a provider is configured, never its credentials."
    ),
)
def platform_config() -> PlatformConfig:
    return PlatformConfig(
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
        max_upload_bytes=settings.max_upload_bytes,
        delete_uploads_after_analysis=settings.delete_uploads_after_analysis,
        dns_lookups_enabled=settings.enable_dns_lookups,
        active_url_fetch_enabled=settings.enable_active_url_fetch,
        rate_limit_requests=settings.rate_limit_requests,
        rate_limit_window_seconds=settings.rate_limit_window_seconds,
        risk_bands=bands_reference(),
        providers=registry.provider_status(),
        edge=_edge_status(),
        access=AccessStatus(**access.posture()),
    )


def _edge_status() -> EdgeStatus:
    """Describe how client identity is resolved, and flag incoherent setups.

    Two configurations are individually valid but wrong together, and neither
    raises an error at runtime -- which is exactly why they are reported here:

    * a forwarding header named with no trusted proxies -> the header is
      ignored, so the operator believes client IPs are resolved when they are
      not;
    * trusted proxies with no header named -> every client behind the proxy
      collapses into one rate-limit bucket.
    """
    entries = settings.trusted_proxy_list
    header = settings.client_ip_header.strip().lower()
    networks = cloudflare.expand(entries)
    behind_cloudflare = any(e.strip().lower() == cloudflare.TOKEN for e in entries)
    trusted = bool(networks) and bool(header)

    warning = None
    if header and not networks:
        warning = (
            f"CLIENT_IP_HEADER is set to '{header}' but TRUSTED_PROXIES is empty, so the "
            "header is ignored and the socket peer is used. Set TRUSTED_PROXIES."
        )
    elif networks and not header:
        warning = (
            "TRUSTED_PROXIES is set but CLIENT_IP_HEADER is empty, so every client behind "
            "the proxy shares one rate-limit bucket. Set CLIENT_IP_HEADER."
        )

    if trusted:
        source = f"'{header}' header, trusted from {len(networks)} proxy range(s)"
        if behind_cloudflare:
            source = f"'{header}' header, trusted from the Cloudflare edge"
    else:
        source = "socket peer (forwarding headers ignored)"

    return EdgeStatus(
        client_ip_source=source,
        trusted_proxy_count=len(networks),
        behind_cloudflare=behind_cloudflare,
        forwarding_headers_trusted=trusted,
        warning=warning,
    )
