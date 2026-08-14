"""Optional shared-token access gate.

Context: the platform has no user accounts by design, which is fine on
localhost and stops being fine the moment it is published through a tunnel --
the API has a DELETE endpoint and a real database behind it. This gate is what
stands between the public internet and that endpoint on a temporary
deployment.

The properties that matter: off by default, closed when on, and not bypassable
by the obvious tricks.
"""

from __future__ import annotations

import io

import pytest

TOKEN = "s3cret-demo-token-value"


@pytest.fixture
def gated(monkeypatch):
    from app.core import config

    monkeypatch.setattr(config.settings, "access_token", TOKEN)
    monkeypatch.setattr(config.settings, "access_protected_methods", "*")
    return TOKEN


class TestDisabledByDefault:
    def test_no_token_configured_means_no_gate(self, client):
        """Local development must not need a token."""
        assert client.get("/api/config").status_code == 200
        assert client.post("/api/analyze/url", json={"url": "https://example.com"}).status_code == 201

    def test_blank_token_does_not_enable_the_gate(self, client, monkeypatch):
        """A stray whitespace value must not lock the instance."""
        from app.core import config

        monkeypatch.setattr(config.settings, "access_token", "   ")
        assert client.get("/api/config").status_code == 200


class TestGateClosed:
    def test_unauthenticated_request_is_refused(self, client, gated):
        response = client.get("/api/config")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "access_denied"

    def test_submission_is_refused(self, client, gated):
        response = client.post("/api/analyze/url", json={"url": "https://example.com"})
        assert response.status_code == 401

    def test_deletion_is_refused(self, client, gated):
        """The endpoint that makes public exposure genuinely dangerous."""
        assert client.delete("/api/analyses/SC-ANYTHING").status_code == 401

    def test_history_is_refused(self, client, gated):
        assert client.get("/api/analyses").status_code == 401

    def test_wrong_token_is_refused(self, client, gated):
        assert client.get("/api/config", headers={"X-Access-Token": "wrong"}).status_code == 401

    def test_empty_token_header_is_refused(self, client, gated):
        assert client.get("/api/config", headers={"X-Access-Token": ""}).status_code == 401

    def test_token_prefix_is_refused(self, client, gated):
        """Guards against a comparison that stops at the first difference."""
        assert client.get("/api/config", headers={"X-Access-Token": TOKEN[:-1]}).status_code == 401

    def test_query_parameter_is_not_accepted(self, client, gated):
        """A token in the URL leaks into logs, history and Referer headers."""
        assert client.get(f"/api/config?token={TOKEN}").status_code == 401
        assert client.get(f"/api/config?access_token={TOKEN}").status_code == 401


class TestGateOpen:
    def test_x_access_token_header_is_accepted(self, client, gated):
        assert client.get("/api/config", headers={"X-Access-Token": TOKEN}).status_code == 200

    def test_bearer_header_is_accepted(self, client, gated):
        assert client.get("/api/config", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200

    def test_bearer_scheme_is_case_insensitive(self, client, gated):
        assert client.get("/api/config", headers={"Authorization": f"bearer {TOKEN}"}).status_code == 200

    def test_submission_works_with_a_token(self, client, gated):
        response = client.post(
            "/api/analyze/url",
            json={"url": "https://example.com/ok"},
            headers={"X-Access-Token": TOKEN},
        )
        assert response.status_code == 201

    def test_file_upload_works_with_a_token(self, client, gated):
        response = client.post(
            "/api/analyze/file",
            files={"file": ("n.txt", io.BytesIO(b"benign notes"), "text/plain")},
            headers={"X-Access-Token": TOKEN},
        )
        assert response.status_code == 201


class TestAlwaysOpenPaths:
    def test_health_stays_reachable(self, client, gated):
        """Gating health would break container and uptime checks."""
        assert client.get("/api/health").status_code == 200

    def test_health_does_not_leak_analysis_data(self, client, gated):
        body = client.get("/api/health").json()
        assert set(body) == {
            "status", "version", "environment", "database", "providers", "analyses_stored",
        }

    def test_docs_stay_reachable(self, client, gated):
        assert client.get("/openapi.json").status_code == 200


class TestPublicReadMode:
    """Lets a report link be shared while submission and deletion stay closed."""

    @pytest.fixture
    def public_read(self, monkeypatch, gated):
        from app.core import config

        monkeypatch.setattr(config.settings, "access_protected_methods", "POST,PUT,PATCH,DELETE")

    def test_reads_are_allowed(self, client, public_read):
        assert client.get("/api/analyses").status_code == 200
        assert client.get("/api/config").status_code == 200

    def test_writes_still_require_a_token(self, client, public_read):
        assert client.post("/api/analyze/url", json={"url": "https://example.com"}).status_code == 401

    def test_deletion_still_requires_a_token(self, client, public_read):
        assert client.delete("/api/analyses/SC-ANYTHING").status_code == 401

    def test_writes_work_with_a_token(self, client, public_read):
        response = client.post(
            "/api/analyze/url",
            json={"url": "https://example.com/x"},
            headers={"X-Access-Token": TOKEN},
        )
        assert response.status_code == 201


class TestDeleteOnlyMode:
    """The deployment shape actually in use: a fully public site whose data
    cannot be wiped by a passer-by."""

    @pytest.fixture
    def delete_only(self, monkeypatch, gated):
        from app.core import config

        monkeypatch.setattr(config.settings, "access_protected_methods", "DELETE")

    def test_browsing_is_open_to_everyone(self, client, delete_only):
        assert client.get("/api/config").status_code == 200
        assert client.get("/api/analyses").status_code == 200
        assert client.get("/api/stats/dashboard").status_code == 200

    def test_submitting_is_open_to_everyone(self, client, delete_only):
        response = client.post("/api/analyze/url", json={"url": "https://example.com/open"})
        assert response.status_code == 201

    def test_file_upload_is_open_to_everyone(self, client, delete_only):
        response = client.post(
            "/api/analyze/file", files={"file": ("n.txt", io.BytesIO(b"notes"), "text/plain")}
        )
        assert response.status_code == 201

    def test_deletion_requires_the_token(self, client, delete_only):
        created = client.post("/api/analyze/url", json={"url": "https://example.com/keep"})
        reference = created.json()["reference"]

        assert client.delete(f"/api/analyses/{reference}").status_code == 401
        # And the record survives the attempt.
        assert client.get(f"/api/analyses/{reference}").status_code == 200

    def test_deletion_works_with_the_token(self, client, delete_only):
        created = client.post("/api/analyze/url", json={"url": "https://example.com/gone"})
        reference = created.json()["reference"]

        response = client.delete(
            f"/api/analyses/{reference}", headers={"X-Access-Token": TOKEN}
        )
        assert response.status_code == 200
        assert client.get(f"/api/analyses/{reference}").status_code == 404

    def test_posture_is_reported_to_the_ui(self, client, delete_only):
        """The UI must know to prompt on delete rather than on page load."""
        access = client.get("/api/config").json()["access"]
        assert access == {"enabled": True, "protected_methods": ["DELETE"], "public_read": True}

    def test_posture_never_includes_the_token(self, client, delete_only):
        assert TOKEN not in client.get("/api/config").text


class TestPostureReporting:
    def test_open_instance_reports_nothing_protected(self, client):
        access = client.get("/api/config").json()["access"]
        assert access["enabled"] is False
        assert access["protected_methods"] == []

    def test_fully_gated_reports_wildcard(self, client, gated):
        access = client.get("/api/config", headers={"X-Access-Token": TOKEN}).json()["access"]
        assert access["protected_methods"] == ["*"]
        assert access["public_read"] is False


class TestNoSecretLeakage:
    def test_rejection_does_not_reveal_the_token(self, client, gated):
        response = client.get("/api/config", headers={"X-Access-Token": "wrong"})
        assert TOKEN not in response.text

    def test_config_never_exposes_the_token(self, client, gated):
        assert TOKEN not in client.get("/api/config", headers={"X-Access-Token": TOKEN}).text

    def test_health_never_exposes_the_token(self, client, gated):
        assert TOKEN not in client.get("/api/health").text
