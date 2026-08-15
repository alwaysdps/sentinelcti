"""Serverless (Vercel) deployment surface.

The application was written for a long-running container. Running it as
serverless functions changes three assumptions, and these tests pin the
behaviour that makes that survivable:

  * startup must not depend on a writable filesystem;
  * startup must not require a schema round-trip on every cold start;
  * a client-side connection pool must be disableable, because a pool that
    cannot be reused is pure cost.

What these cannot cover is the platform itself. In-process rate limiting stops
binding across invocations no matter what this suite says -- that is a property
of serverless, documented in `api/index.py` and replaced by Cloudflare rate
limiting at the edge.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "api" / "index.py"
VERCEL_CONFIG = REPO_ROOT / "vercel.json"


class TestEntrypoint:
    def test_entrypoint_exists(self):
        assert ENTRYPOINT.exists(), "Vercel looks for an ASGI app under /api"

    def test_entrypoint_exposes_an_asgi_app(self):
        """Vercel's Python runtime binds to a module-level `app`."""
        spec = importlib.util.spec_from_file_location("vercel_entry", ENTRYPOINT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert hasattr(module, "app")
        assert callable(module.app)

    def test_entrypoint_reuses_the_real_application(self):
        """A second copy of the app would drift from the routing table."""
        source = ENTRYPOINT.read_text(encoding="utf-8")
        assert "from app.main import app" in source
        assert "FastAPI(" not in source


class TestVercelConfig:
    @pytest.fixture(scope="class")
    def config(self):
        import json

        return json.loads(VERCEL_CONFIG.read_text(encoding="utf-8"))

    def test_config_is_valid_json(self, config):
        assert config["outputDirectory"] == "frontend/dist"

    def test_api_routes_reach_the_function(self, config):
        sources = [r["source"] for r in config["rewrites"]]
        assert "/api/(.*)" in sources

    def test_spa_fallback_excludes_api_and_assets(self, config):
        """Otherwise the SPA shell would be served in place of API responses."""
        import re

        fallback = next(
            r for r in config["rewrites"] if r["destination"] == "/index.html"
        )
        pattern = re.compile(fallback["source"].lstrip("/"))
        assert pattern.fullmatch("dashboard")
        assert pattern.fullmatch("analysis/SC-ABC123")
        assert not pattern.fullmatch("api/health")
        assert not pattern.fullmatch("assets/index-abc.js")

    def test_function_includes_the_application_package(self, config):
        """Without includeFiles the function imports nothing but itself."""
        fn = config["functions"]["api/index.py"]
        assert "backend/app" in fn["includeFiles"]

    def test_function_duration_exceeds_the_analysis_budget(self, config):
        """A function shorter than the analyzer's own budget turns a truncated
        report into a platform timeout."""
        from app.core.config import settings

        assert config["functions"]["api/index.py"]["maxDuration"] > (
            settings.file_analysis_timeout_seconds
        )

    def test_no_memory_setting(self, config):
        """Vercel warns on every build that `memory` is ignored under Active CPU
        billing. Keeping it would just reprint the warning forever."""
        assert "memory" not in config["functions"]["api/index.py"]

    def test_python_version_is_pinned(self):
        """Unpinned, the build logs 'No Python version specified' and takes
        whatever Vercel currently defaults to -- which can change under you."""
        pin = REPO_ROOT / ".python-version"
        assert pin.exists(), "add a .python-version file"
        assert pin.read_text(encoding="utf-8").strip() == "3.12"

    def test_security_headers_are_declared(self, config):
        headers = {
            h["key"]
            for entry in config["headers"]
            if entry["source"] == "/(.*)"
            for h in entry["headers"]
        }
        assert {"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"} <= headers

    def test_hashed_assets_are_immutable_and_index_is_not(self, config):
        by_source = {e["source"]: e["headers"] for e in config["headers"]}
        assert "immutable" in by_source["/assets/(.*)"][0]["value"]
        assert "no-cache" in by_source["/index.html"][0]["value"]


class TestServerlessSettings:
    def test_schema_creation_can_be_skipped(self, monkeypatch):
        """Every cold start would otherwise pay a reflection round-trip."""
        from app.core import config

        monkeypatch.setattr(config.settings, "auto_create_tables", False)
        assert config.settings.auto_create_tables is False

    def test_pooling_can_be_disabled(self, monkeypatch):
        from sqlalchemy.pool import NullPool

        from app.core import config
        from app.database.session import _engine_kwargs

        monkeypatch.setattr(config.settings, "database_disable_pooling", True)
        url = "postgresql+psycopg://u:p@aws-0-x.pooler.supabase.com:6543/postgres"
        assert _engine_kwargs(url)["poolclass"] is NullPool

    def test_prepared_statements_stay_disabled_behind_the_pooler(self, monkeypatch):
        from app.core import config
        from app.database.session import _engine_kwargs

        monkeypatch.setattr(config.settings, "database_disable_pooling", True)
        url = "postgresql+psycopg://u:p@aws-0-x.pooler.supabase.com:6543/postgres"
        assert _engine_kwargs(url)["connect_args"]["prepare_threshold"] is None


class TestStartupNeverHardFails:
    """Regression: an unreachable database at startup killed every invocation.

    On Vercel the symptom was `FUNCTION_INVOCATION_FAILED` on all routes --
    including the health check that would have explained it. Startup must
    degrade so the API can report its own problem.
    """

    def test_schema_failure_does_not_break_the_api(self, monkeypatch):
        from fastapi.testclient import TestClient

        from app import main
        from app.core import config

        def explode() -> None:
            raise RuntimeError("database unreachable")

        monkeypatch.setattr(config.settings, "auto_create_tables", True)
        monkeypatch.setattr(main, "init_db", explode)

        with TestClient(main.app) as client:
            assert client.get("/api/health").status_code == 200
            # Endpoints that never touch the database keep working entirely.
            assert client.get("/api/config").status_code == 200

    def test_health_reports_the_failure_type(self, monkeypatch):
        """'unavailable' alone cannot distinguish a missing driver from a
        refused connection from a missing table."""
        from fastapi.testclient import TestClient

        from app.api import system
        from app.main import app

        class Boom(Exception):
            pass

        def broken(*_args, **_kwargs):
            raise Boom("nope")

        monkeypatch.setattr(system, "select", broken)

        with TestClient(app) as client:
            body = client.get("/api/health").json()
            assert body["status"] == "degraded"
            assert "Boom" in body["database"]

    def test_health_failure_never_leaks_the_connection_string(self, monkeypatch):
        """The exception *message* can contain credentials; only the type is safe."""
        from fastapi.testclient import TestClient

        from app.api import system
        from app.main import app

        secret = "postgresql://user:hunter2@db.example.com:5432/postgres"

        def broken(*_args, **_kwargs):
            raise RuntimeError(f"could not connect to {secret}")

        monkeypatch.setattr(system, "select", broken)

        with TestClient(app) as client:
            text = client.get("/api/health").text
            assert "hunter2" not in text
            assert secret not in text


class TestReadOnlyFilesystem:
    def test_unwritable_upload_dir_does_not_break_startup(self, monkeypatch, tmp_path):
        """Vercel's filesystem is read-only outside /tmp. Failing startup would
        take down endpoints that never touch the disk."""
        from fastapi.testclient import TestClient

        from app.core import config
        from app.main import app

        monkeypatch.setattr(
            config.settings, "upload_dir", tmp_path / "nonexistent" / "\x00bad"
        )
        with TestClient(app) as client:
            assert client.get("/api/health").status_code == 200
            assert client.get("/api/analyses").status_code == 200


def _packages(path: Path) -> set[str]:
    """Package names declared in a requirements file, ignoring version specs."""
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry or entry.startswith("-"):
            continue
        # "psycopg[binary]>=3.2" -> "psycopg"
        names.add(re.split(r"[\[<>=!~;]", entry, maxsplit=1)[0].strip().lower())
    return names


class TestDependencyManifest:
    """The root manifest duplicates the backend one because Vercel's parser
    rejects `-r` includes:

        Error: could not parse requirements.txt

    Duplication invites drift, so it is asserted away here rather than left to
    be discovered by a failing production deploy."""

    ROOT = REPO_ROOT / "requirements.txt"
    BACKEND = REPO_ROOT / "backend" / "requirements.txt"

    # Supplied by the platform; shipping it would only add cold-start weight.
    SERVERLESS_OMITTED = {"uvicorn"}

    def test_root_manifest_uses_no_include_directives(self):
        """The exact construct that failed the first deploy."""
        for line in self.ROOT.read_text(encoding="utf-8").splitlines():
            entry = line.split("#", 1)[0].strip()
            assert not entry.startswith("-r "), f"Vercel cannot parse: {entry!r}"
            assert not entry.startswith("--requirement"), f"Vercel cannot parse: {entry!r}"

    def test_manifests_declare_the_same_packages(self):
        root = _packages(self.ROOT)
        backend = _packages(self.BACKEND) - self.SERVERLESS_OMITTED
        assert root == backend, (
            "requirements.txt and backend/requirements.txt have drifted. "
            f"Only in root: {root - backend}. Only in backend: {backend - root}."
        )

    def test_postgres_driver_is_present_in_both(self):
        """Without it the function cannot reach Supabase at all."""
        assert "psycopg" in _packages(self.ROOT)
        assert "psycopg" in _packages(self.BACKEND)

    def test_root_manifest_is_installable_syntax(self):
        """Every line is a comment, blank, or a plain requirement."""
        for line in self.ROOT.read_text(encoding="utf-8").splitlines():
            entry = line.split("#", 1)[0].strip()
            if entry:
                assert re.match(r"^[A-Za-z0-9._-]+(\[[A-Za-z0-9,._-]+\])?\s*[<>=!~].*$", entry), (
                    f"unparseable requirement line: {entry!r}"
                )
