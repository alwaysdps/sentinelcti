"""PostgreSQL/Supabase compatibility, verified without a live database.

Portability claims are cheap to make and easy to get wrong. Every query in the
application is compiled here against the real PostgreSQL dialect, so a
statement that only happens to work on SQLite fails in CI rather than the first
time someone points DATABASE_URL at Supabase.

What this cannot cover -- an actual network round-trip, TLS negotiation and
credentials -- is what `scripts/check_db.py` is for.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from app.database.session import Base, _engine_kwargs, uses_transaction_pooler
from app.models.analysis import Analysis
from app.models.enums import IndicatorType, Verdict

PG = postgresql.dialect()

SUPABASE_TX_POOLER = (
    "postgresql+psycopg://postgres.abcdefghijklm:pw@aws-0-eu-west-2.pooler.supabase.com:6543/postgres"
)
SUPABASE_SESSION_POOLER = (
    "postgresql+psycopg://postgres.abcdefghijklm:pw@aws-0-eu-west-2.pooler.supabase.com:5432/postgres"
)
SUPABASE_DIRECT = "postgresql+psycopg://postgres:pw@db.abcdefghijklm.supabase.co:5432/postgres"


def compile_pg(statement) -> str:
    return str(statement.compile(dialect=PG, compile_kwargs={"literal_binds": True}))


class TestSchemaPortability:
    def test_analyses_table_compiles_for_postgresql(self):
        ddl = str(CreateTable(Analysis.__table__).compile(dialect=PG))
        assert "CREATE TABLE analyses" in ddl

    def test_json_columns_become_jsonb_on_postgresql(self):
        """JSONB is queryable with containment operators; JSON text is not."""
        ddl = str(CreateTable(Analysis.__table__).compile(dialect=PG))
        for column in ("findings", "details", "provider_results", "mitre_techniques"):
            assert f"{column} JSONB" in ddl

    def test_json_columns_stay_json_on_sqlite(self):
        ddl = str(CreateTable(Analysis.__table__).compile(dialect=sqlite.dialect()))
        assert "JSONB" not in ddl

    def test_timestamps_are_timezone_aware_on_postgresql(self):
        ddl = str(CreateTable(Analysis.__table__).compile(dialect=PG))
        assert "TIMESTAMP WITH TIME ZONE" in ddl

    def test_every_model_table_compiles(self):
        for table in Base.metadata.tables.values():
            assert str(CreateTable(table).compile(dialect=PG))


class TestQueryPortability:
    def test_history_filters_compile(self):
        from app.services.query_service import _apply_filters

        statement = _apply_filters(
            select(Analysis),
            search="evil",
            indicator_type=IndicatorType.URL,
            verdict=Verdict.HIGH_RISK,
            min_score=10,
            max_score=90,
        )
        sql = compile_pg(statement)
        assert "ILIKE" in sql.upper()
        assert "risk_score" in sql

    def test_dashboard_aggregates_compile(self):
        assert compile_pg(select(Analysis.verdict, func.count()).group_by(Analysis.verdict))
        assert compile_pg(select(func.avg(Analysis.risk_score)))
        assert compile_pg(select(func.count()).select_from(Analysis))

    def test_activity_series_uses_date_trunc_on_postgresql(self):
        """`date()` is SQLite's spelling; PostgreSQL needs date_trunc."""
        from app.services.query_service import _day_bucket

        class FakeBind:
            dialect = PG

        class FakeSession:
            bind = FakeBind()

        sql = compile_pg(select(_day_bucket(FakeSession())))
        assert "date_trunc" in sql.lower()

    def test_activity_series_uses_date_on_sqlite(self):
        from app.services.query_service import _day_bucket

        class FakeBind:
            dialect = sqlite.dialect()

        class FakeSession:
            bind = FakeBind()

        sql = str(select(_day_bucket(FakeSession())).compile(dialect=sqlite.dialect()))
        assert "date(" in sql.lower()
        assert "date_trunc" not in sql.lower()

    def test_day_key_normalises_every_dialect_return_type(self):
        from datetime import date, datetime, timezone

        from app.services.query_service import _day_key

        assert _day_key(datetime(2026, 8, 14, 9, 30, tzinfo=timezone.utc)) == "2026-08-14"
        assert _day_key(date(2026, 8, 14)) == "2026-08-14"
        assert _day_key("2026-08-14") == "2026-08-14"
        assert _day_key("2026-08-14 00:00:00") == "2026-08-14"


class TestSupabaseConnectionHandling:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (SUPABASE_TX_POOLER, True),
            (SUPABASE_SESSION_POOLER, False),
            (SUPABASE_DIRECT, False),
            ("postgresql+psycopg://u:p@localhost:5432/db?pgbouncer=true", True),
        ],
    )
    def test_transaction_pooler_detection(self, url, expected):
        assert uses_transaction_pooler(url) is expected

    def test_transaction_pooler_disables_prepared_statements(self):
        """PgBouncer transaction mode cannot support server-side prepares."""
        kwargs = _engine_kwargs(SUPABASE_TX_POOLER)
        assert kwargs["connect_args"]["prepare_threshold"] is None

    def test_transaction_pooler_still_uses_a_client_side_pool(self):
        """Measured: a cross-region handshake costs ~1s. Without a client pool,
        SQLAlchemy reconnects after every commit and batches time out."""
        kwargs = _engine_kwargs(SUPABASE_TX_POOLER)
        assert "poolclass" not in kwargs
        assert kwargs["pool_size"] > 0
        assert kwargs["pool_pre_ping"] is True

    def test_pooling_can_be_disabled_for_serverless(self, monkeypatch):
        from sqlalchemy.pool import NullPool

        from app.core import config

        monkeypatch.setattr(config.settings, "database_disable_pooling", True)
        assert _engine_kwargs(SUPABASE_TX_POOLER)["poolclass"] is NullPool

    def test_disabled_pooling_still_disables_prepared_statements(self, monkeypatch):
        """The pgbouncer constraint is independent of the pooling choice."""
        from app.core import config

        monkeypatch.setattr(config.settings, "database_disable_pooling", True)
        kwargs = _engine_kwargs(SUPABASE_TX_POOLER)
        assert kwargs["connect_args"]["prepare_threshold"] is None

    def test_session_pooler_keeps_a_local_pool(self):
        kwargs = _engine_kwargs(SUPABASE_SESSION_POOLER)
        assert "poolclass" not in kwargs
        assert kwargs["pool_pre_ping"] is True
        assert kwargs["pool_recycle"] > 0

    def test_session_pooler_keeps_prepared_statements_enabled(self):
        """Session mode supports them; disabling would forfeit a real speedup."""
        assert "prepare_threshold" not in _engine_kwargs(SUPABASE_SESSION_POOLER)["connect_args"]

    def test_connect_timeout_absorbs_a_slow_cross_region_handshake(self):
        assert _engine_kwargs(SUPABASE_TX_POOLER)["connect_args"]["connect_timeout"] >= 15

    def test_tls_is_required_for_postgres(self):
        for url in (SUPABASE_TX_POOLER, SUPABASE_SESSION_POOLER, SUPABASE_DIRECT):
            assert _engine_kwargs(url)["connect_args"]["sslmode"] == "require"

    def test_connect_timeout_is_bounded(self):
        assert _engine_kwargs(SUPABASE_DIRECT)["connect_args"]["connect_timeout"] > 0

    def test_sqlite_settings_are_untouched_by_postgres_tuning(self):
        kwargs = _engine_kwargs("sqlite:///./test.db")
        assert kwargs["connect_args"] == {"check_same_thread": False}
        assert "sslmode" not in kwargs["connect_args"]


class TestConnectionStringPreflight:
    """Catch malformed URLs before connecting, where the driver's own error
    would name the wrong thing entirely."""

    def check(self, monkeypatch, url: str) -> list[str]:
        from app.core import config
        from scripts.check_db import preflight

        monkeypatch.setattr(config.settings, "database_url", url)
        return preflight()

    def test_valid_url_reports_no_problems(self, monkeypatch):
        assert self.check(monkeypatch, SUPABASE_TX_POOLER) == []

    def test_sqlite_is_never_preflighted(self, monkeypatch):
        assert self.check(monkeypatch, "sqlite:///./x.db") == []

    def test_unencoded_at_in_password_is_detected(self, monkeypatch):
        """The nastiest failure: it surfaces as a DNS error, not an auth error."""
        url = "postgresql+psycopg://postgres.abc:pa@ss@aws-0-eu-west-2.pooler.supabase.com:6543/postgres"
        problems = self.check(monkeypatch, url)
        assert any("unencoded '@'" in p for p in problems)

    def test_encoded_at_is_accepted(self, monkeypatch):
        url = "postgresql+psycopg://postgres.abc:pa%40ss@aws-0-eu-west-2.pooler.supabase.com:6543/postgres"
        assert self.check(monkeypatch, url) == []

    def test_placeholder_brackets_are_detected(self, monkeypatch):
        url = "postgresql+psycopg://postgres.abc:[secret]@aws-0-eu-west-2.pooler.supabase.com:6543/postgres"
        assert any("square brackets" in p for p in self.check(monkeypatch, url))

    def test_unreplaced_placeholder_is_detected(self, monkeypatch):
        url = "postgresql+psycopg://postgres.abc:YOUR-PASSWORD@aws-0-eu-west-2.pooler.supabase.com:6543/postgres"
        assert any("placeholder" in p for p in self.check(monkeypatch, url))

    def test_bare_postgres_username_is_detected_for_the_pooler(self, monkeypatch):
        url = "postgresql+psycopg://postgres:secret@aws-0-eu-west-2.pooler.supabase.com:6543/postgres"
        assert any("postgres.<project-ref>" in p for p in self.check(monkeypatch, url))

    def test_bare_postgres_username_is_fine_for_a_direct_connection(self, monkeypatch):
        assert self.check(monkeypatch, SUPABASE_DIRECT) == []

    def test_malformed_url_does_not_crash_pooler_detection(self):
        """urlsplit raises on '[' in the authority; detection must survive it."""
        assert uses_transaction_pooler(
            "postgresql+psycopg://u:[p]@aws-0-eu-west-2.pooler.supabase.com:6543/postgres"
        )


class TestCredentialSafety:
    def test_redacted_url_hides_the_password(self, monkeypatch):
        from app.core import config
        from scripts.check_db import redacted_url

        monkeypatch.setattr(config.settings, "database_url", SUPABASE_TX_POOLER)
        redacted = redacted_url()
        assert "pw" not in redacted.split("@")[0].replace("***", "")
        assert "***" in redacted
        assert "pooler.supabase.com" in redacted

    def test_config_endpoint_never_exposes_the_database_url(self, client):
        body = client.get("/api/config").json()
        serialised = str(body).lower()
        assert "postgresql" not in serialised
        assert "supabase" not in serialised
        assert "password" not in serialised
