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


class TestDependencyManifest:
    def test_root_requirements_defers_to_backend(self):
        """One dependency list, not two that drift apart."""
        text = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
        assert "-r backend/requirements.txt" in text

    def test_postgres_driver_is_present(self):
        text = (REPO_ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8")
        assert "psycopg" in text
