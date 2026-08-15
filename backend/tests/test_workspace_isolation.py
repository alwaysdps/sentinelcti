"""Anonymous per-browser workspace isolation.

Before this existed, every visitor shared one pool: your dashboard counted
other people's scans, your history listed their submissions, and any `SC-`
reference opened any report. For a tool whose inputs are suspicious URLs and
internal hostnames, that is a disclosure problem, not a tidiness one.

The rule under test is one line — *your own analyses, plus shared demo data* —
and these tests assert it holds at every door into the data: listing, single
report, dashboard aggregates, activity series, and deletion.
"""

from __future__ import annotations

import io

import pytest

ALICE = "a" * 32
BOB = "b" * 32
HEADER = "X-Owner-Key"


def as_alice(client, method: str, path: str, **kwargs):
    return client.request(method, path, headers={HEADER: ALICE}, **kwargs)


def as_bob(client, method: str, path: str, **kwargs):
    return client.request(method, path, headers={HEADER: BOB}, **kwargs)


@pytest.fixture
def alice_analysis(client):
    response = as_alice(
        client, "POST", "/api/analyze/url", json={"url": "https://alice-private.example/secret"}
    )
    assert response.status_code == 201
    return response.json()


class TestSubmissionsAreOwned:
    def test_alice_sees_her_own_analysis(self, client, alice_analysis):
        body = as_alice(client, "GET", "/api/analyses").json()
        assert alice_analysis["reference"] in [i["reference"] for i in body["items"]]

    def test_bob_cannot_see_alices_history(self, client, alice_analysis):
        body = as_bob(client, "GET", "/api/analyses").json()
        assert alice_analysis["reference"] not in [i["reference"] for i in body["items"]]

    def test_bob_cannot_open_alices_report_by_reference(self, client, alice_analysis):
        """References are short. An unscoped lookup would make them guessable."""
        response = as_bob(client, "GET", f"/api/analyses/{alice_analysis['reference']}")
        assert response.status_code == 404

    def test_bob_cannot_open_alices_report_by_numeric_id(self, client, alice_analysis):
        """The id path is a second door to the same row and needs the same lock."""
        response = as_bob(client, "GET", f"/api/analyses/{alice_analysis['id']}")
        assert response.status_code == 404

    def test_a_caller_with_no_key_cannot_see_alices_analysis(self, client, alice_analysis):
        body = client.get("/api/analyses").json()
        assert alice_analysis["reference"] not in [i["reference"] for i in body["items"]]

    def test_alices_indicator_never_appears_in_bobs_responses(self, client, alice_analysis):
        """The indicator itself is the sensitive part — an internal hostname or
        a live phishing URL under investigation."""
        for path in ("/api/analyses", "/api/stats/dashboard"):
            assert "alice-private.example" not in as_bob(client, "GET", path).text


class TestFileSubmissionsAreOwned:
    def test_uploaded_filename_is_not_visible_to_others(self, client):
        created = as_alice(
            client,
            "POST",
            "/api/analyze/file",
            files={"file": ("payroll-internal.txt", io.BytesIO(b"notes"), "text/plain")},
        )
        assert created.status_code == 201
        assert "payroll-internal" not in as_bob(client, "GET", "/api/analyses").text


class TestDashboardIsScoped:
    def test_counts_exclude_other_workspaces(self, client):
        before = as_bob(client, "GET", "/api/stats/dashboard").json()["total_analyses"]
        for i in range(3):
            as_alice(client, "POST", "/api/analyze/url", json={"url": f"https://example.com/{i}"})
        after = as_bob(client, "GET", "/api/stats/dashboard").json()["total_analyses"]
        assert after == before, "Bob's dashboard counted Alice's submissions"

    def test_own_counts_do_increase(self, client):
        before = as_alice(client, "GET", "/api/stats/dashboard").json()["total_analyses"]
        as_alice(client, "POST", "/api/analyze/url", json={"url": "https://example.com/mine"})
        after = as_alice(client, "GET", "/api/stats/dashboard").json()["total_analyses"]
        assert after == before + 1

    def test_recent_list_is_scoped(self, client, alice_analysis):
        recent = as_bob(client, "GET", "/api/stats/dashboard").json()["recent"]
        assert alice_analysis["reference"] not in [r["reference"] for r in recent]

    def test_activity_series_is_scoped(self, client):
        """The series would otherwise leak another workspace's submission volume."""
        for i in range(2):
            as_alice(client, "POST", "/api/analyze/url", json={"url": f"https://example.com/a{i}"})
        bob = as_bob(client, "GET", "/api/stats/dashboard?activity_days=7").json()
        assert sum(point["count"] for point in bob["activity"]) == 0


class TestDeletionRequiresOwnership:
    def test_bob_cannot_delete_alices_analysis(self, client, alice_analysis):
        assert as_bob(client, "DELETE", f"/api/analyses/{alice_analysis['reference']}").status_code == 404
        # And it survives.
        assert as_alice(client, "GET", f"/api/analyses/{alice_analysis['reference']}").status_code == 200

    def test_alice_can_delete_her_own(self, client, alice_analysis):
        assert as_alice(client, "DELETE", f"/api/analyses/{alice_analysis['reference']}").status_code == 200
        assert as_alice(client, "GET", f"/api/analyses/{alice_analysis['reference']}").status_code == 404

    def test_keyless_caller_cannot_delete_anything(self, client, alice_analysis):
        assert client.delete(f"/api/analyses/{alice_analysis['reference']}").status_code == 404


class TestSharedDemoData:
    """Seeded rows belong to no workspace and are visible to everyone, so a
    first-time visitor sees a populated dashboard rather than an empty one."""

    @pytest.fixture
    def demo_row(self, client):
        from app.database import SessionLocal
        from app.models.analysis import Analysis

        db = SessionLocal()
        try:
            row = Analysis(
                reference="SC-DEMO01",
                indicator_type="url",
                indicator="https://demo.example/",
                indicator_display="https://demo.example/",
                risk_score=0,
                verdict="clean",
                status="completed",
                findings=[],
                details={},
                provider_results=[],
                mitre_techniques=[],
                duration_seconds=0.0,
                is_demo=True,
                owner_key=None,
            )
            db.add(row)
            db.commit()
            return "SC-DEMO01"
        finally:
            db.close()

    def test_demo_rows_are_visible_to_every_workspace(self, client, demo_row):
        for caller in (as_alice, as_bob):
            refs = [i["reference"] for i in caller(client, "GET", "/api/analyses").json()["items"]]
            assert demo_row in refs

    def test_demo_rows_are_visible_without_any_key(self, client, demo_row):
        refs = [i["reference"] for i in client.get("/api/analyses").json()["items"]]
        assert demo_row in refs

    def test_demo_rows_cannot_be_deleted(self, client, demo_row):
        """Nobody owns them, so nobody may empty a new visitor's dashboard."""
        assert as_alice(client, "DELETE", f"/api/analyses/{demo_row}").status_code == 404
        assert client.get(f"/api/analyses/{demo_row}").status_code == 200


class TestKeyValidation:
    @pytest.mark.parametrize(
        "key",
        ["", "short", "has spaces in it" + "x" * 20, "a" * 65, "semi;colon" + "x" * 25],
    )
    def test_malformed_keys_are_treated_as_no_workspace(self, client, key):
        """A malformed key must not become a workspace of its own, or junk in
        the header would silently fragment a user's history."""
        created = client.post(
            "/api/analyze/url", json={"url": "https://example.com/x"}, headers={HEADER: key}
        )
        assert created.status_code == 201
        # Unowned: not visible to any workspace, including a repeat of the same
        # malformed key.
        listing = client.get("/api/analyses", headers={HEADER: key}).json()
        assert created.json()["reference"] not in [i["reference"] for i in listing["items"]]

    def test_valid_key_shapes_are_accepted(self, client):
        from app.core.owner import is_valid_key

        assert is_valid_key("a" * 32)
        assert is_valid_key("f" * 64)
        assert is_valid_key("A-Za-z0-9_-" + "x" * 25)
        assert not is_valid_key(None)
        assert not is_valid_key("a" * 31)


class TestSingleVisibilityRule:
    def test_every_read_path_uses_the_shared_predicate(self):
        """Guards against a future query forgetting to scope — the one mistake
        that would silently reopen the leak this feature closed."""
        from pathlib import Path

        source = Path("app/services/query_service.py").read_text(encoding="utf-8")
        # Listing, dashboard counts and the activity series must all reference it.
        assert source.count("visible_to(owner_key)") >= 2
        assert "where(scope)" in source
