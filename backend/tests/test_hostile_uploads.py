"""Adversarial upload tests.

These are regression tests for a real, reproduced defect: the original
whole-blob domain regex was O(n^2), so a small file of `a.a.a.a...` padded to
the scan window would have pinned a worker for hours. Because file analysis
also ran inline on the event loop, that single upload took the whole API down.

Each test below encodes one property that must hold no matter what bytes the
submitter chooses:

  * analysis completes in bounded time;
  * hostile content cannot corrupt what an operator reads;
  * nothing hostile survives on disk;
  * concurrent submissions cannot exhaust the service.
"""

from __future__ import annotations

import io
import time

import pytest

from app.analyzers import file_analyzer
from app.analyzers.extract import AnalysisBudget, extract_all
from app.core.sanitize import defang, scrub
from app.services import storage

# Generous relative to the ~10 s production budget: the point is to catch
# superlinear blow-ups, not to benchmark the host.
TIME_LIMIT_SECONDS = 8.0

SCAN = file_analyzer.MAX_TEXT_SCAN_BYTES


def payload(pattern: bytes, total: int = SCAN) -> bytes:
    return (pattern * (total // len(pattern) + 1))[:total]


# Byte sequences chosen to stress a different part of the pipeline each.
ADVERSARIAL_PAYLOADS: dict[str, bytes] = {
    # The original O(n^2) trigger.
    "domain_backtrack": payload(b"a."),
    "domain_backtrack_long_labels": payload(b"a" * 60 + b"."),
    "nested_subdomains": payload(b"a.b.c.d.e.f.g.h."),
    # Nested-quantifier bait for the Windows path matcher.
    "windows_path_run": payload(b"C:\\" + b"a" * 200),
    "path_separators": payload(b"C:\\a\\b\\c\\"),
    # Extractor stress: unbounded candidate counts.
    "many_unique_domains": b" ".join(b"host%d.example.com" % i for i in range(40000))[:SCAN],
    "many_urls": payload(b"http://a.example.com/x "),
    "many_ips": payload(b"203.0.113.9 "),
    "many_emails": payload(b"user@example.com "),
    # Blob detectors.
    "one_huge_base64": payload(b"QUJDREVGR0hJSktMTU5PUFFS"),
    "one_huge_hex": payload(b"deadbeef"),
    # Degenerate byte distributions.
    "all_nulls": b"\x00" * SCAN,
    "all_spaces": b" " * SCAN,
    "no_delimiters": b"a" * SCAN,
    "alternating": payload(b"\x00a"),
    # Content that also matches suspicious patterns, so the full sweep runs.
    "suspicious_and_hostile": payload(b"powershell -EncodedCommand AAAA a.b.c. C:\\x\\y "),
}


class TestNoUnboundedWork:
    """A hostile sample must not be able to monopolise a worker."""

    @pytest.mark.parametrize("name", sorted(ADVERSARIAL_PAYLOADS))
    def test_analysis_of_adversarial_payload_completes_quickly(self, name, tmp_upload):
        data = ADVERSARIAL_PAYLOADS[name]
        path = tmp_upload(data, f"{name}.txt")

        start = time.perf_counter()
        result = file_analyzer.analyze(path, f"{name}.txt", f"{name}.txt", len(data))
        elapsed = time.perf_counter() - start

        assert elapsed < TIME_LIMIT_SECONDS, f"{name} took {elapsed:.1f}s"
        # It must still be a usable report, not a bail-out.
        assert result.details["hashes"]["sha256"]

    @pytest.mark.parametrize("name", sorted(ADVERSARIAL_PAYLOADS))
    def test_extraction_alone_is_bounded(self, name):
        text = ADVERSARIAL_PAYLOADS[name].decode("utf-8", errors="replace")
        start = time.perf_counter()
        found = extract_all(text, limit=50)
        elapsed = time.perf_counter() - start

        assert elapsed < TIME_LIMIT_SECONDS, f"{name} took {elapsed:.1f}s"
        # Result size is capped regardless of how many candidates exist.
        assert len(found.urls) <= 50
        assert len(found.domains) <= 50
        assert len(found.ipv4) <= 50
        assert len(found.emails) <= 50

    def test_extraction_scales_linearly_not_quadratically(self):
        """The specific regression: 4x the input must not cost ~16x the time."""
        base = "a." * 20000
        timings = []
        for multiplier in (1, 4):
            text = base * multiplier
            start = time.perf_counter()
            extract_all(text, limit=50)
            timings.append(max(time.perf_counter() - start, 1e-4))

        growth = timings[1] / timings[0]
        # Quadratic would be ~16x. Allow generous headroom for a noisy host.
        assert growth < 10, f"extraction grew {growth:.1f}x for 4x input"


class TestBudgetEnforcement:
    def test_expired_budget_stops_extraction(self):
        budget = AnalysisBudget(0.0)
        assert budget.expired

    def test_budget_records_truncation(self):
        budget = AnalysisBudget(0.0)
        _ = budget.expired
        assert budget.truncated is True

    def test_truncated_analysis_is_reported_not_hidden(self, tmp_upload):
        """A shortened sweep must never be presented as a complete clean scan."""
        data = payload(b"http://a.example.com/x powershell -EncodedCommand AA ")
        path = tmp_upload(data, "big.txt")

        # Zero budget forces truncation deterministically.
        result = file_analyzer.analyze(
            path, "big.txt", "big.txt", len(data), budget=AnalysisBudget(0.0)
        )

        codes = {s.code for s in result.signals}
        assert "file_analysis_truncated" in codes
        assert result.details["analysis_truncated"] is True
        assert result.status.value == "partial"

    def test_untruncated_analysis_is_not_flagged(self, tmp_upload):
        path = tmp_upload(b"a short benign note\n", "small.txt")
        result = file_analyzer.analyze(path, "small.txt", "small.txt", 20)
        assert "file_analysis_truncated" not in {s.code for s in result.signals}
        assert result.status.value == "completed"


class TestOutputNeutralisation:
    """Sample content reaches a browser, a log and a database column."""

    def test_control_and_ansi_sequences_are_stripped(self):
        assert "\x1b" not in scrub("\x1b[31mFAKE ALERT\x1b[0m")
        assert "\r" not in scrub("line\roverwrite")
        assert "\x00" not in scrub("nul\x00byte")

    def test_bidi_override_is_removed(self):
        # U+202E is what makes "exe.txt" render as "txt.exe".
        assert "\u202e" not in scrub("invoice\u202etxt.exe")

    def test_zero_width_characters_are_removed(self):
        assert scrub("ma\u200blic\u200dious") == "malicious"

    def test_legitimate_content_survives(self):
        assert scrub("powershell -EncodedCommand AAAA") == "powershell -EncodedCommand AAAA"
        assert scrub("naïve café 日本語") == "naïve café 日本語"

    def test_long_strings_are_capped(self):
        assert len(scrub("A" * 5000)) <= 200

    def test_nul_bytes_never_reach_stored_details(self, tmp_upload):
        """PostgreSQL rejects NUL in text columns; a sample must not cause that."""
        data = b"http://evil\x00.example.com/\x00path powershell\x00 -EncodedCommand AA"
        path = tmp_upload(data, "nul.txt")
        result = file_analyzer.analyze(path, "nul.txt", "nul.txt", len(data))
        assert "\x00" not in repr(result.details)

    def test_hostile_filename_is_neutralised_in_details(self, tmp_upload):
        path = tmp_upload(b"content", "x.txt")
        result = file_analyzer.analyze(
            path, "invoice\u202egpj.exe", storage.sanitize_filename("invoice.exe"), 7
        )
        assert "\u202e" not in result.details["original_filename"]

    def test_extracted_indicators_are_defanged(self, tmp_upload):
        data = b"beacon to http://malware.example.com/c2 and 203.0.113.66\n"
        path = tmp_upload(data, "ioc.txt")
        result = file_analyzer.analyze(path, "ioc.txt", "ioc.txt", len(data))

        indicators = result.details["embedded_indicators"]
        assert all(not u.startswith("http://") for u in indicators["urls"])
        assert all("[.]" in ip for ip in indicators["ipv4"])

    def test_defang_is_reversible_in_meaning_only(self):
        assert defang("http://evil.example.com/a.exe") == "hxxp://evil[.]example[.]com/a.exe"
        assert defang("203.0.113.66") == "203[.]0[.]113[.]66"


class TestNothingHostileSurvives:
    def test_sample_bytes_are_removed_even_when_analysis_is_truncated(self, client):
        data = payload(b"a.", 200_000)
        client.post(
            "/api/analyze/file",
            files={"file": ("hostile.txt", io.BytesIO(data), "text/plain")},
        )
        assert list(storage.quarantine_root().iterdir()) == []

    def test_quarantine_capacity_is_enforced(self, monkeypatch):
        from app.core import config
        from app.core.errors import CapacityExceeded

        monkeypatch.setattr(config.settings, "max_quarantine_bytes", 1)
        with pytest.raises(CapacityExceeded):
            storage.store_stream([b"anything"])

    def test_capacity_check_reports_actual_usage(self):
        assert storage.quarantine_usage_bytes() == 0


class TestApiRemainsUsable:
    def test_hostile_upload_returns_a_normal_report(self, client):
        data = payload(b"a.b.c.", 300_000)
        response = client.post(
            "/api/analyze/file",
            files={"file": ("adversarial.txt", io.BytesIO(data), "text/plain")},
        )
        assert response.status_code == 201
        assert response.json()["details"]["hashes"]["sha256"]

    def test_api_still_serves_other_requests_after_a_hostile_upload(self, client):
        data = payload(b"a.", 300_000)
        client.post(
            "/api/analyze/file", files={"file": ("x.txt", io.BytesIO(data), "text/plain")}
        )
        health = client.get("/api/health").json()
        assert health["status"] == "ok"
        assert health["database"].startswith("connected")

    def test_response_contains_no_raw_control_characters(self, client):
        data = b"\x1b[31mALERT\x1b[0m http://a.example.com/\x07 beep"
        response = client.post(
            "/api/analyze/file", files={"file": ("ansi.txt", io.BytesIO(data), "text/plain")}
        )
        assert "\x1b" not in response.text
        assert "\x07" not in response.text
