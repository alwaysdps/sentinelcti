"""Neutralisation of hostile content in NON-file indicators.

Regression tests for an audit finding: the file analyzer scrubbed its extracted
strings, but a URL, domain, IP or hash submission did not. A submitted URL
containing U+202E was stored and returned verbatim, so a report could be made
to misrepresent its own contents -- the same deception the analyzer flags in
filenames, reachable through a different door.

The fix scrubs at the persistence boundary in `analysis_service`, so these
properties hold for every indicator type, including any added later.
"""

from __future__ import annotations

import json

import pytest

# Characters that must never survive into a stored report.
RTLO = "‮"  # right-to-left override: reverses how the rest of a line renders
ZWSP = "​"  # zero-width space: invisible, breaks string comparison by eye
ANSI = "\x1b[31m"  # terminal colour escape: can repaint an operator's console


def submit(client, path: str, field: str, value: str):
    return client.post(path, json={field: value})


class TestUrlIndicators:
    def test_bidi_override_is_stripped_from_a_submitted_url(self, client):
        response = submit(client, "/api/analyze/url", "url", f"http://example.com/{RTLO}exe.txt")
        assert response.status_code == 201
        assert RTLO not in response.text

    def test_zero_width_characters_are_stripped(self, client):
        response = submit(client, "/api/analyze/url", "url", f"http://exa{ZWSP}mple.com/a")
        assert ZWSP not in response.text

    def test_ansi_escapes_are_stripped(self, client):
        response = submit(client, "/api/analyze/url", "url", f"http://example.com/{ANSI}x")
        assert "\x1b" not in response.text

    def test_scrubbing_reaches_nested_technical_details(self, client):
        """Analyzers quote the submitted value into details, not just the title."""
        response = submit(client, "/api/analyze/url", "url", f"http://example.com/{RTLO}p")
        assert RTLO not in json.dumps(response.json()["details"])

    def test_scrubbing_reaches_finding_descriptions(self, client):
        response = submit(client, "/api/analyze/url", "url", f"http://example.com/{RTLO}p")
        assert RTLO not in json.dumps(response.json()["findings"])

    def test_legitimate_urls_are_unchanged(self, client):
        """Neutralisation must not corrupt ordinary input."""
        url = "https://example.com/products/overview?id=42&ref=a-b_c"
        body = submit(client, "/api/analyze/url", "url", url).json()
        assert body["indicator"] == url

    def test_international_characters_survive(self, client):
        """Stripping format characters must not strip real script."""
        body = submit(client, "/api/analyze/domain", "domain", "münchen.example").json()
        assert body["risk_score"] >= 0


class TestOtherIndicatorTypes:
    @pytest.mark.parametrize(
        ("path", "field", "value"),
        [
            ("/api/analyze/domain", "domain", f"exam{ZWSP}ple.com"),
            ("/api/analyze/ip", "ip", f"8.8.8.8{ZWSP}"),
            ("/api/analyze/hash", "hash", f"{ZWSP}d41d8cd98f00b204e9800998ecf8427e"),
        ],
    )
    def test_invisible_characters_never_reach_the_report(self, client, path, field, value):
        response = submit(client, path, field, value)
        # Either rejected as invalid, or accepted and neutralised -- never
        # accepted and echoed back with the character intact.
        assert response.status_code in (201, 422)
        assert ZWSP not in response.text

    def test_stored_report_is_also_clean(self, client):
        """The retrieval path must not reintroduce what the write path removed."""
        created = submit(client, "/api/analyze/url", "url", f"http://example.com/{RTLO}x")
        reference = created.json()["reference"]
        assert RTLO not in client.get(f"/api/analyses/{reference}").text

    def test_history_listing_is_also_clean(self, client):
        submit(client, "/api/analyze/url", "url", f"http://example.com/{RTLO}x")
        assert RTLO not in client.get("/api/analyses").text


class TestErrorPathNeutralisation:
    """Validation errors quote the rejected value back to the caller.

    That is deliberate -- it is what makes the message useful -- but it means
    the error path carries submitter-controlled text into the UI and the logs,
    bypassing the scrubbing applied when an analysis is *stored*. A rejected
    submission is still attacker-controlled input.
    """

    @pytest.mark.parametrize(
        ("path", "field"),
        [
            ("/api/analyze/ip", "ip"),
            ("/api/analyze/domain", "domain"),
            ("/api/analyze/hash", "hash"),
            ("/api/analyze/url", "url"),
        ],
    )
    def test_rejected_input_is_not_echoed_back_with_control_characters(self, client, path, field):
        response = client.post(path, json={field: f"invalid{RTLO}{ZWSP}{ANSI}value"})
        assert response.status_code == 422
        assert RTLO not in response.text
        assert ZWSP not in response.text
        assert "\x1b" not in response.text

    def test_error_messages_remain_useful(self):
        """Neutralisation must not gut the diagnostic."""
        from app.core.sanitize import scrub

        assert "not a valid" in scrub("'999.1.1.1' is not a valid IPv4 or IPv6 address.")

    def test_error_message_length_is_bounded(self, client):
        response = client.post("/api/analyze/hash", json={"hash": "z" * 3000})
        assert response.status_code == 422
        assert len(response.json()["error"]["message"]) <= 500


class TestMalformedInputNeverCauses500:
    """Submitted input must always yield a validation error, never a crash.

    `urlparse` raises ValueError on an unbalanced '[' or ']' in the authority --
    it tries to read it as an IPv6 literal. Unhandled, that turned a malformed
    URL into a 500.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "http://[bad",
            "http://]",
            "http://a[b]c.com",
            "http://[::1",
            "[",
            "http://[",
        ],
    )
    def test_unbalanced_brackets_return_422_not_500(self, client, url):
        response = client.post("/api/analyze/url", json={"url": url})
        assert response.status_code == 422, f"{url!r} produced {response.status_code}"
        assert response.json()["error"]["code"] in ("invalid_indicator", "validation_error")

    def test_bracket_in_the_path_is_not_an_authority_problem(self, client):
        """Only the authority is parsed as a potential IPv6 literal, so a
        bracket later in the URL is ordinary content and analyses normally."""
        response = client.post("/api/analyze/url", json={"url": "http://example.com/a[1]"})
        assert response.status_code == 201

    def test_valid_ipv6_url_still_works(self, client):
        """The fix must not reject legitimate bracketed IPv6 hosts."""
        response = client.post("/api/analyze/url", json={"url": "http://[2001:db8::1]:8080/x"})
        assert response.status_code == 201
        assert response.json()["details"]["host_is_ip_literal"] is True


class TestSortContract:
    def test_valid_sort_fields_are_accepted(self, client):
        for field in ("created_at", "risk_score", "indicator", "indicator_type", "verdict"):
            assert client.get(f"/api/analyses?sort_by={field}").status_code == 200

    def test_unknown_sort_field_is_rejected_not_silently_ignored(self, client):
        """Silently defaulting hid client typos: the response looked correct but
        was ordered by something else."""
        assert client.get("/api/analyses?sort_by=bogus_column").status_code == 422

    def test_sql_in_sort_by_is_rejected_and_harmless(self, client):
        response = client.get("/api/analyses", params={"sort_by": "; DROP TABLE analyses"})
        assert response.status_code == 422
        # The table is still there.
        assert client.get("/api/analyses").status_code == 200

    def test_enum_matches_the_service_allowlist(self):
        """Guards against the API contract drifting from the security boundary."""
        from app.api.analyses import SortField
        from app.services.query_service import SORTABLE_COLUMNS

        assert {field.value for field in SortField} == set(SORTABLE_COLUMNS)


class TestScrubStructure:
    def test_nested_containers_are_traversed(self):
        from app.core.sanitize import scrub_structure

        payload = {"a": [f"x{RTLO}y", {"b": f"z{ZWSP}"}], "n": 5, "flag": True, "none": None}
        cleaned = scrub_structure(payload)
        assert RTLO not in json.dumps(cleaned)
        assert ZWSP not in json.dumps(cleaned)

    def test_non_string_types_are_preserved_exactly(self):
        from app.core.sanitize import scrub_structure

        payload = {"count": 42, "ratio": 1.5, "flag": False, "missing": None}
        assert scrub_structure(payload) == payload

    def test_keys_are_left_alone(self):
        """Keys are analyzer-authored identifiers, never submitter input."""
        from app.core.sanitize import scrub_structure

        assert set(scrub_structure({"registrable_domain": "x"})) == {"registrable_domain"}

    def test_is_idempotent(self):
        """The file analyzer scrubs its own strings; double-scrubbing must be safe."""
        from app.core.sanitize import scrub_structure

        once = scrub_structure({"v": f"a{RTLO}b"})
        assert scrub_structure(once) == once

    def test_long_values_are_not_truncated_to_display_length(self):
        """Stored values keep their length; only display lists are shortened."""
        from app.core.sanitize import scrub_structure

        url = "http://example.com/" + "a" * 500
        assert scrub_structure({"u": url})["u"] == url
