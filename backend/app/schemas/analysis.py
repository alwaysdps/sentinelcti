"""Request and response contracts.

Validation lives at the boundary. Each request model constrains length and
shape *before* any analyzer sees the value, so an analyzer can assume it is
working with something bounded. Response models are explicit rather than
returning ORM objects directly, which keeps internal column changes from
silently altering the public API.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..models.enums import AnalysisStatus, IndicatorType, Verdict


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------
class URLAnalysisRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="Absolute http/https URL. A missing scheme is assumed to be http.",
        examples=["http://secure-login.paypal.account-verify.example/login"],
    )

    @field_validator("url")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class DomainAnalysisRequest(BaseModel):
    domain: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description="Bare domain name, without scheme, path or port.",
        examples=["cdn-update-service.example"],
    )

    @field_validator("domain")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip().rstrip(".")


class IPAnalysisRequest(BaseModel):
    ip: str = Field(
        ...,
        min_length=2,
        max_length=45,  # longest textual IPv6 form
        description="IPv4 or IPv6 address.",
        examples=["203.0.113.66"],
    )

    @field_validator("ip")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class HashAnalysisRequest(BaseModel):
    hash: str = Field(
        ...,
        min_length=32,
        max_length=64,
        description="MD5 (32), SHA-1 (40) or SHA-256 (64) hexadecimal digest.",
        examples=["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"],
    )

    @field_validator("hash")
    @classmethod
    def _normalise(cls, v: str) -> str:
        return v.strip().lower()


# --------------------------------------------------------------------------
# Responses
# --------------------------------------------------------------------------
class Finding(BaseModel):
    code: str = Field(description="Stable identifier for this check.")
    title: str
    description: str
    points: int = Field(description="Points this finding contributed to the risk score.")
    severity: str = Field(description="pass | info | low | medium | high")
    category: str
    mitre: list[str] = Field(default_factory=list, description="Potential ATT&CK technique IDs.")


class ProviderResultOut(BaseModel):
    provider: str
    result: str = Field(description="malicious | suspicious | clean | unknown | error")
    detail: str
    score_contribution: int = 0
    reference_url: str | None = None


class MitreTechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactic: str
    url: str
    confidence: str = Field(
        description="Always 'potential association' -- static evidence never proves execution."
    )


class ScoreBreakdownItem(BaseModel):
    code: str
    title: str
    points: int
    severity: str
    category: str


class ScoringOut(BaseModel):
    score: int
    verdict: str
    summary: str
    base_points: int
    corroboration_bonus: int
    floor_applied: int = Field(
        default=0,
        description="Minimum score forced by a positive identification, if one raised the score.",
    )
    floor_reason: str | None = None
    capped_at_maximum: bool
    breakdown: list[ScoreBreakdownItem]


class AnalysisSummary(BaseModel):
    """Row shape used by the history table and dashboard lists."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    reference: str
    indicator_type: IndicatorType
    indicator_display: str
    risk_score: int
    verdict: Verdict
    status: AnalysisStatus
    created_at: datetime
    duration_seconds: float
    is_demo: bool


class AnalysisDetail(AnalysisSummary):
    """Full report payload."""

    indicator: str
    findings: list[Finding]
    details: dict
    provider_results: list[ProviderResultOut]
    mitre_techniques: list[MitreTechniqueOut]


class PaginatedAnalyses(BaseModel):
    items: list[AnalysisSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class ActivityPoint(BaseModel):
    date: str
    count: int
    malicious: int


class DashboardStats(BaseModel):
    total_analyses: int
    malicious_count: int = Field(description="High-risk and critical verdicts combined.")
    suspicious_count: int
    clean_count: int = Field(description="Clean and low-risk verdicts combined.")
    average_risk_score: float
    by_verdict: dict[str, int]
    by_indicator_type: dict[str, int]
    activity: list[ActivityPoint]
    recent: list[AnalysisSummary]


class RiskBand(BaseModel):
    min: int
    max: int
    verdict: str
    summary: str


class ProviderStatus(BaseModel):
    name: str
    display_name: str
    enabled: bool
    configured: bool
    requires_network: bool


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database: str
    providers: list[ProviderStatus]
    analyses_stored: int


class AccessStatus(BaseModel):
    """What the access gate protects. Never the token itself.

    The UI needs this to decide whether to offer a token prompt: a fully open
    instance must not show a login form that gates nothing, and a
    DELETE-only instance must prompt on delete rather than on page load.
    """

    enabled: bool = Field(description="Whether an access token is configured.")
    protected_methods: list[str] = Field(
        default_factory=list,
        description="HTTP methods requiring the token. ['*'] means all.",
    )
    public_read: bool = Field(
        default=False, description="Whether GET requests are open to everyone."
    )


class EdgeStatus(BaseModel):
    """How the platform identifies a client, and whether that is coherent.

    Surfaced because the failure mode is silent. Deploy behind a CDN without
    setting TRUSTED_PROXIES and every request is attributed to an edge address:
    rate limiting still *runs*, it just buckets the whole internet together, and
    nothing in the logs says so. Reporting the resolved source turns that into
    something an operator can see on the Settings page.

    Reports posture, never the proxy list itself.
    """

    client_ip_source: str = Field(description="Where the client address is read from.")
    trusted_proxy_count: int = Field(description="Number of trusted proxy ranges configured.")
    behind_cloudflare: bool = Field(description="Whether Cloudflare edge ranges are trusted.")
    forwarding_headers_trusted: bool = Field(
        description="Whether any forwarding header is honoured. False means the socket peer is always used."
    )
    warning: str | None = Field(
        default=None,
        description="Set when the proxy configuration is internally inconsistent.",
    )


class PlatformConfig(BaseModel):
    """Read-only capability report consumed by the Settings page.

    Deliberately excludes every secret: it reports *whether* a provider is
    configured, never the key that configures it.
    """

    app_name: str
    version: str
    environment: str
    max_upload_bytes: int
    delete_uploads_after_analysis: bool
    dns_lookups_enabled: bool
    active_url_fetch_enabled: bool
    rate_limit_requests: int
    rate_limit_window_seconds: int
    risk_bands: list[RiskBand]
    providers: list[ProviderStatus]
    edge: EdgeStatus
    access: AccessStatus


class DeleteResponse(BaseModel):
    deleted: bool
    reference: str


class PurgeResponse(BaseModel):
    """Result of emptying the caller's own workspace."""

    deleted: int
