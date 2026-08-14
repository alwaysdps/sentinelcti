"""Shared test fixtures.

The application settings are patched *before* `app` is imported so the test run
never touches the developer's real database, quarantine directory, or the
network. Each test module gets its own throwaway SQLite file.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TMP_ROOT = Path(tempfile.mkdtemp(prefix="sentinelcti-tests-"))
_TEST_DB_URL = f"sqlite:///{(_TMP_ROOT / 'test.db').as_posix()}"

# Assigned, not setdefault(). The suite creates and DELETES analyses, so an
# inherited DATABASE_URL -- a developer who exported one for a Supabase
# session, a CI job with it in the environment -- would run destructive tests
# against a real database. The test database is never negotiable.
os.environ["DATABASE_URL"] = _TEST_DB_URL
os.environ["UPLOAD_DIR"] = str(_TMP_ROOT / "quarantine")
# Deterministic tests must not depend on a working resolver.
os.environ["ENABLE_DNS_LOOKUPS"] = "false"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["ENVIRONMENT"] = "test"

# Deployment settings are neutralised for the same reason as DATABASE_URL:
# `backend/.env` is read by pydantic-settings, so anything an operator puts
# there leaks into the suite. Setting ACCESS_TOKEN for a tunnel deployment once
# turned 64 tests red with 401s -- the tests were correct and the environment
# was not, which is the most expensive kind of failure to diagnose.
#
# Tests that need these features set them explicitly with monkeypatch.
os.environ["ACCESS_TOKEN"] = ""
os.environ["ACCESS_PROTECTED_METHODS"] = "*"
os.environ["TRUSTED_PROXIES"] = ""
os.environ["CLIENT_IP_HEADER"] = ""
os.environ["ENABLE_ACTIVE_URL_FETCH"] = "false"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import delete  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.analysis import Analysis  # noqa: E402

# Belt and braces: if a future change to settings precedence ever lets the
# real URL win, fail the run immediately rather than mutate a live database.
if settings.access_token or settings.trusted_proxies:
    raise RuntimeError(
        "Refusing to run tests: deployment settings leaked into the test "
        f"environment (access_token set: {bool(settings.access_token)}, "
        f"trusted_proxies: {settings.trusted_proxies!r}). Tests must be "
        "hermetic; set these with monkeypatch inside the tests that need them."
    )

if settings.database_url != _TEST_DB_URL:
    raise RuntimeError(
        "Refusing to run tests: settings.database_url is not the throwaway test "
        f"database (got {settings.database_url!r}). The suite performs "
        "destructive writes and must never target a real database."
    )


@pytest.fixture(scope="session", autouse=True)
def _database():
    init_db()
    yield


@pytest.fixture(autouse=True)
def _clean_table():
    """Every test starts from an empty table so counts are assertable."""
    db = SessionLocal()
    try:
        db.execute(delete(Analysis))
        db.commit()
    finally:
        db.close()
    yield


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def tmp_upload(tmp_path: Path):
    """Write bytes to a temp file and return its path, mimicking quarantine."""

    def _write(content: bytes, name: str = "sample.bin") -> Path:
        path = tmp_path / name
        path.write_bytes(content)
        return path

    return _write
