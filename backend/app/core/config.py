"""Application configuration.

All tunables live here so that no analyzer, service or route reads os.environ
directly. That keeps secrets and deployment-specific values in exactly one
place, which is the only way to reliably audit them.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(BACKEND_ROOT / ".env", BACKEND_ROOT.parent / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- General -----------------------------------------------------------
    app_name: str = "SentinelCTI"
    app_version: str = "1.0.0"
    environment: str = Field(default="development")
    debug: bool = Field(default=True)

    # --- Database ----------------------------------------------------------
    # A full SQLAlchemy URL. Swapping SQLite for PostgreSQL (Supabase or
    # otherwise) is a matter of setting DATABASE_URL -- no code changes,
    # because every query goes through the ORM.
    #
    #   Supabase transaction pooler (recommended: IPv4, works everywhere):
    #     postgresql+psycopg://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:6543/postgres
    #   Supabase session pooler:
    #     ...pooler.supabase.com:5432/postgres
    database_url: str = Field(default=f"sqlite:///{(BACKEND_ROOT / 'sentinelcti.db').as_posix()}")

    # PostgreSQL connection tuning. Ignored entirely when using SQLite.
    database_sslmode: str = Field(default="require")
    # Applies per resolved address, and a pooler hostname resolves to several.
    # A cross-region handshake was measured at ~1s, so 15s absorbs a slow link
    # without letting a genuinely dead endpoint hang startup for a minute.
    database_connect_timeout: int = Field(default=15)
    database_pool_size: int = Field(default=5)
    database_max_overflow: int = Field(default=5)
    # Set true only for short-lived processes (serverless, one-shot jobs) where
    # a client-side pool cannot be reused before the process exits. For a
    # long-running server this costs a full TCP+TLS handshake per commit.
    database_disable_pooling: bool = Field(default=False)
    # Run create_all() at startup. Convenient locally; wasteful on serverless,
    # where every cold start would pay a schema-reflection round-trip to a
    # database that already has the tables. Set false once the schema exists
    # (created by `python -m scripts.check_db --create`).
    auto_create_tables: bool = Field(default=True)
    # None = auto-detect from the URL (port 6543 / pgbouncer=true). Set
    # explicitly only if you have an unusual topology the heuristic misreads.
    database_transaction_pooler: bool | None = Field(default=None)

    # --- CORS --------------------------------------------------------------
    cors_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173")

    # --- Uploads -----------------------------------------------------------
    max_upload_bytes: int = Field(default=10 * 1024 * 1024)  # 10 MB
    # Deliberately outside any statically served directory: uploaded content is
    # never reachable over HTTP, so a stored payload can never be re-served.
    upload_dir: Path = Field(default=BACKEND_ROOT / "var" / "quarantine")
    # Uploads are transient by design. Hashes and metadata are what have
    # intelligence value; keeping the bytes only increases blast radius.
    delete_uploads_after_analysis: bool = Field(default=True)
    max_strings_extracted: int = Field(default=2000)
    max_request_bytes: int = Field(default=12 * 1024 * 1024)

    # --- Analysis resource limits -----------------------------------------
    # Availability is part of the safety model: a sample that makes the
    # analyzer burn unbounded CPU takes the service down as surely as one that
    # executes code, and needs no exploit to do it. These three bounds are what
    # keep a hostile upload from becoming a denial of service.

    # Cooperative wall-clock deadline for one file's static analysis. Exceeding
    # it yields a truncated, explicitly-labelled report rather than a hung
    # worker.
    file_analysis_timeout_seconds: float = Field(default=10.0)

    # Simultaneous file analyses. Each one occupies a worker thread and up to
    # ~1 MB of scan buffer, so this caps both thread pressure and memory.
    max_concurrent_file_analyses: int = Field(default=4)

    # Ceiling on total bytes resident in the quarantine directory. Uploads are
    # deleted immediately after analysis, so this is only ever reached by
    # concurrent submissions -- it stops a burst from filling the disk.
    max_quarantine_bytes: int = Field(default=256 * 1024 * 1024)

    # --- Rate limiting -----------------------------------------------------
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_requests: int = Field(default=60)
    rate_limit_window_seconds: int = Field(default=60)
    # Ceiling on distinct clients tracked at once. Without it the limiter's
    # bucket map grows for every address ever seen, which is a slow memory
    # exhaustion primitive rather than a leak in the ordinary sense.
    rate_limit_max_tracked_clients: int = Field(default=10_000)

    # --- Optional access gate ----------------------------------------------
    # Empty (the default) = no gate, which is correct on localhost. Set it
    # before publishing the app through a tunnel: the API has a DELETE endpoint
    # and a real database behind it. See core/access.py for what this is and,
    # more importantly, what it is not.
    access_token: str = Field(default="")
    # Which HTTP methods require the token. "*" protects everything; a
    # comma-separated list protects only those methods.
    #
    # This is what makes "open to everyone, except destructive actions"
    # expressible: ACCESS_PROTECTED_METHODS=DELETE leaves browsing and
    # submission completely public while stopping a passer-by from emptying
    # the database.
    access_protected_methods: str = Field(default="*")

    # --- Reverse proxy / CDN ----------------------------------------------
    # Forwarding headers are attacker-controlled unless the request demonstrably
    # came from a proxy we trust. Empty list (the default) = never trust them,
    # always use the socket peer. See core/client_ip.py.
    #
    # Behind Cloudflare, these two lines are the whole configuration -- the
    # `cloudflare` token expands to the published edge ranges (core/cloudflare.py):
    #   TRUSTED_PROXIES=cloudflare
    #   CLIENT_IP_HEADER=cf-connecting-ip
    trusted_proxies: str = Field(default="")
    client_ip_header: str = Field(default="")

    # --- Network-touching features (all opt-out) --------------------------
    # DNS resolution is passive and does not contact the indicator itself, so
    # it is on by default. Anything that would send traffic *to* a submitted
    # indicator is off by default and must be enabled deliberately.
    enable_dns_lookups: bool = Field(default=True)
    dns_timeout_seconds: float = Field(default=3.0)
    enable_active_url_fetch: bool = Field(default=False)

    # --- Threat intelligence providers ------------------------------------
    # Comma separated list of provider names to enable. "local" is the offline
    # heuristic engine and is always safe to run.
    enabled_providers: str = Field(default="local")
    virustotal_api_key: str = Field(default="")
    abuseipdb_api_key: str = Field(default="")

    @field_validator("upload_dir", mode="before")
    @classmethod
    def _coerce_path(cls, value: object) -> object:
        return Path(value) if isinstance(value, str) else value

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def provider_list(self) -> list[str]:
        return [p.strip().lower() for p in self.enabled_providers.split(",") if p.strip()]

    @property
    def protected_method_set(self) -> set[str]:
        """Methods requiring the access token. Empty set means "all"."""
        raw = self.access_protected_methods.strip()
        if raw in ("", "*"):
            return set()
        return {m.strip().upper() for m in raw.split(",") if m.strip()}

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
