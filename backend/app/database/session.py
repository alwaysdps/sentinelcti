"""Engine and session management.

Everything the application does with the database goes through SQLAlchemy's
ORM/Core expression layer, which parameterises values. No route or service
builds SQL by string concatenation, so user-supplied indicators can never be
interpreted as SQL.

Supported backends: SQLite (zero-config default) and PostgreSQL, including
Supabase. Switching is a `DATABASE_URL` change and nothing else -- see
`_engine_kwargs` for the two places where the backends genuinely differ.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool

from ..core.config import settings


class Base(DeclarativeBase):
    pass


def is_postgres(url: str) -> bool:
    return url.startswith(("postgresql", "postgres://"))


def uses_transaction_pooler(url: str) -> bool:
    """Detect a PgBouncer-style transaction pooler in front of PostgreSQL.

    Supabase offers three connection paths and the choice changes what the
    driver is allowed to do:

    * **Direct** (port 5432) -- a real PostgreSQL connection. IPv6-only on
      current Supabase projects, which breaks on IPv4-only hosts and CI.
    * **Session pooler** (port 5432 via `*.pooler.supabase.com`) -- IPv4, and
      behaves like a direct connection.
    * **Transaction pooler** (port 6543) -- IPv4, connection-per-transaction.
      Server-side prepared statements are NOT supported here, and psycopg3
      creates them automatically after a few executions. Left alone that
      surfaces as sporadic `DuplicatePreparedStatement` errors under load,
      which is a genuinely unpleasant bug to diagnose in production.

    Detection is by port/hostname with an explicit override, so an unusual
    topology can still be configured rather than mis-detected.
    """
    if settings.database_transaction_pooler is not None:
        return settings.database_transaction_pooler
    try:
        parts = urlsplit(url)
        return parts.port == 6543 or "pgbouncer=true" in (parts.query or "")
    except ValueError:
        # A malformed authority (an unencoded bracket, say) makes urlsplit
        # raise. Detection is a best-effort optimisation; connecting will fail
        # with a useful message shortly regardless.
        return ":6543" in url or "pgbouncer=true" in url


def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        # SQLite objects are bound to the creating thread by default; FastAPI
        # runs sync endpoints in a threadpool, hence check_same_thread=False.
        return {"connect_args": {"check_same_thread": False}, "pool_pre_ping": True}

    if is_postgres(url):
        connect_args: dict = {
            # Supabase terminates TLS at the edge and rejects plaintext. Being
            # explicit also stops a misconfigured host from silently
            # downgrading to an unencrypted connection.
            "sslmode": settings.database_sslmode,
            "connect_timeout": settings.database_connect_timeout,
            "application_name": f"{settings.app_name}/{settings.app_version}",
        }

        if uses_transaction_pooler(url):
            # prepare_threshold=None disables psycopg3's automatic prepared
            # statements, which PgBouncer's transaction mode cannot support.
            connect_args["prepare_threshold"] = None

        if settings.database_disable_pooling:
            # For short-lived processes (serverless, Lambda, a one-shot job) a
            # client-side pool is dead weight -- the process exits before it
            # can be reused.
            return {"connect_args": connect_args, "poolclass": NullPool}

        # A client-side pool in front of the Supabase pooler is deliberate, and
        # was measured: a fresh connection to a remote region costs ~1s of
        # TCP+TLS handshake. Without pooling, SQLAlchemy returns the connection
        # after every commit, so a batch of writes pays that repeatedly and
        # starts hitting connect timeouts. Pooling is safe here because
        # PgBouncer's transaction mode multiplexes at the transaction boundary
        # and the client pool only ever holds pooler-side connections -- the
        # thing it must NOT do (server-side prepared statements) is already
        # disabled above.
        return {
            "connect_args": connect_args,
            "pool_pre_ping": True,  # discards connections the pooler dropped
            "pool_size": settings.database_pool_size,
            "max_overflow": settings.database_max_overflow,
            # Comfortably under Supabase's idle timeout, so the application
            # never hands out a connection the server has already closed.
            "pool_recycle": 1800,
            "pool_timeout": 30,
        }

    return {"pool_pre_ping": True}


def _ensure_sqlite_dir(url: str) -> None:
    prefix = "sqlite:///"
    if url.startswith(prefix):
        path = Path(url[len(prefix) :])
        if path.parent and str(path.parent) not in ("", "."):
            path.parent.mkdir(parents=True, exist_ok=True)


_ensure_sqlite_dir(settings.database_url)

engine: Engine = create_engine(settings.database_url, echo=False, **_engine_kwargs(settings.database_url))

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def _sqlite_pragmas(dbapi_connection, _record) -> None:
    """Enable foreign keys and WAL on SQLite; both are off by default."""
    if settings.database_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


def backend_name() -> str:
    """Human-readable backend description for /api/health."""
    if settings.database_url.startswith("sqlite"):
        return "sqlite"
    if is_postgres(settings.database_url):
        try:
            host = urlsplit(settings.database_url).hostname or ""
        except ValueError:
            host = settings.database_url
        if "supabase" in host:
            mode = "transaction pooler" if uses_transaction_pooler(settings.database_url) else "direct"
            return f"postgresql (supabase, {mode})"
        return "postgresql"
    return engine.dialect.name


def init_db() -> None:
    """Create tables. Real deployments would use Alembic migrations instead."""
    from ..models import analysis as _analysis  # noqa: F401  (register metadata)

    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
