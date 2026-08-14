"""Verify the configured database before starting the application.

Connection problems with a hosted PostgreSQL almost always come down to one of
four things: wrong host form, IPv6-only endpoint, missing TLS, or the password
still containing a URL-unsafe character. A generic SQLAlchemy traceback names
none of them, so this script maps each failure onto the thing to actually go
and change.

Usage:
    python -m scripts.check_db
    python -m scripts.check_db --create   # also create missing tables
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, inspect, select, text  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.database.session import (  # noqa: E402
    SessionLocal,
    backend_name,
    engine,
    init_db,
    is_postgres,
    uses_transaction_pooler,
)
from app.models.analysis import Analysis  # noqa: E402

EXPECTED_TABLES = {"analyses"}


def redacted_url() -> str:
    """The URL with the password removed, safe to print or paste into an issue.

    Falls back to a raw string redaction if the URL is too malformed to parse --
    a broken URL is exactly when this needs to work, and it must never print
    the password while failing.
    """
    try:
        parts = urlsplit(settings.database_url)
        if not parts.hostname:
            return settings.database_url
        user = f"{parts.username}:***@" if parts.username else ""
        port = f":{parts.port}" if parts.port else ""
        return f"{parts.scheme}://{user}{parts.hostname}{port}{parts.path}"
    except ValueError:
        scheme, sep, rest = settings.database_url.partition("://")
        if not sep or "@" not in rest:
            return settings.database_url
        userinfo, _, hostpart = rest.rpartition("@")
        username = userinfo.split(":", 1)[0]
        return f"{scheme}://{username}:***@{hostpart}"


def preflight() -> list[str]:
    """Catch malformed connection strings before attempting to connect.

    These three mistakes account for most failed first connections, and all of
    them surface as errors that name the wrong thing -- an unencoded '@' in the
    password reports a DNS failure, because URL parsing split the string at the
    wrong character. Detecting them here means the message points at the actual
    problem.
    """
    url = settings.database_url
    if not is_postgres(url):
        return []

    problems: list[str] = []
    # Everything between the scheme and the final '/' -- i.e. userinfo + host.
    netloc = url.split("://", 1)[-1].split("/", 1)[0]

    if netloc.count("@") > 1:
        problems.append(
            "The password appears to contain an unencoded '@'. URL parsing splits on "
            "the LAST '@', so part of the password is being read as the hostname. "
            "Percent-encode it as %40 (and $ as %24, # as %23, % as %25)."
        )

    userinfo = netloc.rsplit("@", 1)[0]
    if "[" in userinfo or "]" in userinfo:
        problems.append(
            "The password still has square brackets around it. '[YOUR-PASSWORD]' is a "
            "placeholder -- remove the brackets and keep only the password itself."
        )

    for placeholder in ("YOUR-PASSWORD", "PASTE_ENCODED_PASSWORD_HERE", "your-password"):
        if placeholder in url:
            problems.append(f"The placeholder '{placeholder}' has not been replaced.")

    # urlsplit raises on a malformed authority (it reads '[' as an IPv6
    # literal), which is precisely the case checked above -- so this runs only
    # as a best effort and never masks the clearer diagnostics.
    try:
        parts = urlsplit(url)
        if parts.username and parts.hostname and "pooler.supabase.com" in parts.hostname:
            if "." not in parts.username:
                problems.append(
                    f"Username is '{parts.username}', but the Supabase pooler requires "
                    "'postgres.<project-ref>'. Copy the URI from the Transaction pooler tab."
                )
    except ValueError:
        pass

    return problems


def diagnose(exc: Exception) -> list[str]:
    """Turn a driver error into the specific thing to change."""
    message = str(exc).lower()
    hints: list[str] = []

    if "could not translate host name" in message or "name or service not known" in message:
        hints.append(
            "Hostname did not resolve. Check it against Supabase -> Project Settings -> "
            "Database -> Connection string."
        )
    if "network is unreachable" in message or "cannot assign requested address" in message:
        hints.append(
            "Likely IPv6-only. Supabase direct connections (db.<ref>.supabase.co) are "
            "IPv6-only; switch to the pooler host (aws-0-<region>.pooler.supabase.com), "
            "which is reachable over IPv4."
        )
    if "tenant or user not found" in message or "(enotfound) tenant/user" in message:
        hints.append(
            "The pooler rejected the username. It must be 'postgres.<project-ref>' "
            "(e.g. postgres.abcdefghijklmnop), not plain 'postgres'. Copy the exact "
            "URI from Supabase -> Project Settings -> Database -> Connection string, "
            "and check the region in the hostname matches your project."
        )
    if "password authentication failed" in message:
        # Reaching this error proves the username/tenant resolved -- the pooler
        # returns "Tenant or user not found" otherwise. So the username is
        # already known-good and pointing at it would send the reader the wrong
        # way; only the password is in question.
        hints.append(
            "The username and host are correct (the pooler resolved the tenant); only "
            "the password was rejected. Check that you copied the CURRENT password in "
            "full -- if you reset it, the old one stops working immediately."
        )
        try:
            from sqlalchemy.engine import make_url

            password = make_url(settings.database_url).password or ""
            hints.append(
                f"The URL currently supplies a {len(password)}-character password "
                "(after percent-decoding). If that length looks short, it was "
                "probably truncated on copy."
            )
        except Exception:  # noqa: BLE001 - diagnostics must never themselves fail
            pass
    if "ssl" in message or "server does not support ssl" in message:
        hints.append(f"TLS negotiation failed (DATABASE_SSLMODE={settings.database_sslmode}).")
    if "timeout" in message or "timed out" in message:
        hints.append(
            "Connection timed out - usually egress filtering on port "
            f"{urlsplit(settings.database_url).port or 5432}."
        )
    if "prepared statement" in message:
        hints.append(
            "Prepared-statement clash: this is a transaction pooler. Set "
            "DATABASE_TRANSACTION_POOLER=true so psycopg disables them."
        )
    if "no module named 'psycopg'" in message:
        hints.append("Driver missing. Install it with: pip install 'psycopg[binary]'")

    if not hints:
        hints.append("Verify DATABASE_URL in backend/.env against the Supabase dashboard.")
    return hints


def main(create: bool) -> int:
    # Runs before anything that parses the URL: a malformed authority makes
    # urlsplit raise, and a raised ValueError is a far worse message than the
    # specific advice preflight produces.
    problems = preflight()
    if problems:
        print(f"URL     : {redacted_url()}\n")
        print("[fail] The connection string is malformed:\n")
        for problem in problems:
            print(f"  -> {problem}")
        print("\nFix backend/.env and re-run. No connection was attempted.")
        return 1

    print(f"Backend : {backend_name()}")
    print(f"URL     : {redacted_url()}")
    if is_postgres(settings.database_url):
        print(f"Pooler  : {'transaction (prepared statements off)' if uses_transaction_pooler(settings.database_url) else 'direct / session'}")
        print(f"SSL     : {settings.database_sslmode}")
    print()

    try:
        # `version()` is PostgreSQL's spelling; SQLite exposes sqlite_version().
        probe = "SELECT version()" if is_postgres(settings.database_url) else "SELECT sqlite_version()"
        with engine.connect() as conn:
            version = conn.execute(text(probe)).scalar_one()
        print(f"[ ok ] Connected\n       {str(version)[:90]}")
    except Exception as exc:  # noqa: BLE001 - the whole point is to explain it
        print(f"[fail] Could not connect: {type(exc).__name__}")
        print(f"       {str(exc).strip().splitlines()[0][:160]}\n")
        for hint in diagnose(exc):
            print(f"  -> {hint}")
        return 1

    tables = set(inspect(engine).get_table_names())
    missing = EXPECTED_TABLES - tables

    if missing and create:
        print(f"[ .. ] Creating missing tables: {', '.join(sorted(missing))}")
        init_db()
        missing = EXPECTED_TABLES - set(inspect(engine).get_table_names())

    if missing:
        print(f"[fail] Missing tables: {', '.join(sorted(missing))}")
        print("  -> Run: python -m scripts.check_db --create")
        return 1
    print(f"[ ok ] Schema present ({', '.join(sorted(EXPECTED_TABLES))})")

    # A read proves the credentials have SELECT, not merely CONNECT.
    db = SessionLocal()
    try:
        count = db.execute(select(func.count()).select_from(Analysis)).scalar_one()
        print(f"[ ok ] Read query succeeded - {count} analyses stored")
    except Exception as exc:  # noqa: BLE001
        print(f"[fail] Read query failed: {exc}")
        return 1
    finally:
        db.close()

    print("\nDatabase is ready.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check the SentinelCTI database connection.")
    parser.add_argument("--create", action="store_true", help="Create missing tables.")
    raise SystemExit(main(parser.parse_args().create))
