"""File analyzer and quarantine storage behaviour.

Note what these tests assert about safety: filenames are sanitised, oversized
uploads abort mid-stream, and nothing is ever executed. The last one is
structural -- the analyzer only ever opens files with `open(path, "rb")`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.analyzers import file_analyzer
from app.core.errors import PayloadTooLarge
from app.models.enums import IndicatorType
from app.services import storage

TEXT = b"Just some ordinary notes about the weather and nothing else at all.\n"


def run(path: Path, name: str = "sample.txt"):
    return file_analyzer.analyze(path, name, storage.sanitize_filename(name), path.stat().st_size)


def codes(result) -> set[str]:
    return {s.code for s in result.signals}


class TestHashing:
    def test_all_three_digests_are_computed_and_correct(self, tmp_upload):
        path = tmp_upload(TEXT)
        digests = file_analyzer.compute_hashes(path)
        assert digests["md5"] == hashlib.md5(TEXT, usedforsecurity=False).hexdigest()
        assert digests["sha1"] == hashlib.sha1(TEXT, usedforsecurity=False).hexdigest()
        assert digests["sha256"] == hashlib.sha256(TEXT).hexdigest()

    def test_streaming_matches_single_shot_for_multi_chunk_files(self, tmp_upload):
        blob = b"A" * (file_analyzer.HASH_CHUNK_BYTES * 2 + 12345)
        path = tmp_upload(blob)
        assert file_analyzer.compute_hashes(path)["sha256"] == hashlib.sha256(blob).hexdigest()

    def test_sha256_is_used_as_the_stored_indicator(self, tmp_upload):
        result = run(tmp_upload(TEXT))
        assert result.indicator == hashlib.sha256(TEXT).hexdigest()
        assert result.indicator_type is IndicatorType.FILE

    def test_empty_file_is_handled(self, tmp_upload):
        result = run(tmp_upload(b""), "empty.txt")
        assert "file_empty" in codes(result)


class TestTypeIdentification:
    @pytest.mark.parametrize(
        ("content", "expected"),
        [
            (b"MZ\x90\x00\x03", "pe"),
            (b"\x7fELF\x02\x01\x01", "elf"),
            (b"%PDF-1.7\n%\xe2\xe3", "pdf"),
            (b"\x89PNG\r\n\x1a\n", "png"),
            (b"PK\x03\x04\x14\x00", "zip"),
            (b"Plain readable text content here.", "text"),
        ],
    )
    def test_magic_bytes_drive_identification(self, tmp_upload, content, expected):
        result = run(tmp_upload(content), "thing.bin")
        assert result.details["detected_type"] == expected

    def test_extension_content_mismatch_is_high_severity(self, tmp_upload):
        # A PE binary wearing a .txt extension is the masquerading case.
        result = run(tmp_upload(b"MZ\x90\x00" + b"\x00" * 200), "notes.txt")
        assert "file_type_mismatch" in codes(result)
        mismatch = next(s for s in result.signals if s.code == "file_type_mismatch")
        assert mismatch.points >= 20

    def test_consistent_extension_produces_a_pass_finding(self, tmp_upload):
        result = run(tmp_upload(TEXT), "notes.txt")
        assert "file_type_consistent" in codes(result)


class TestStringExtraction:
    def test_printable_runs_are_extracted_from_binary(self):
        data = b"\x00\x01" + b"SuspiciousMarker" + b"\xff\xfe" + b"AnotherLongString"
        found = file_analyzer.extract_strings(data)
        assert "SuspiciousMarker" in found
        assert "AnotherLongString" in found

    def test_short_runs_are_ignored(self):
        assert file_analyzer.extract_strings(b"\x00ab\x00cd\x00") == []

    def test_extraction_respects_the_configured_cap(self):
        data = b"\x00".join(b"marker%03d" % i for i in range(500))
        assert len(file_analyzer.extract_strings(data, limit=10)) == 10

    def test_embedded_urls_and_ips_are_reported(self, tmp_upload):
        content = b"config: http://cdn-update-service.example/x  fallback 203.0.113.66\n"
        result = run(tmp_upload(content), "config.txt")
        assert "file_embedded_urls" in codes(result)
        assert "file_embedded_ips" in codes(result)
        # Indicators are stored defanged so a report can never be one click
        # away from resolving hostile infrastructure.
        assert "203[.]0[.]113[.]66" in result.details["embedded_indicators"]["ipv4"]
        assert all(
            not url.startswith("http://") for url in result.details["embedded_indicators"]["urls"]
        )


class TestSuspiciousPatterns:
    def test_powershell_encoded_command_is_detected_and_mapped(self, tmp_upload):
        content = b"powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=\n"
        result = run(tmp_upload(content), "script.ps1")
        matched = result.details["matched_pattern_codes"]
        assert "ps_encoded_command" in matched
        techniques = {t for s in result.signals for t in s.mitre}
        assert "T1059.001" in techniques

    def test_persistence_and_recovery_destruction_are_detected(self, tmp_upload):
        content = (
            b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v X /d y.exe\n"
            b"vssadmin delete shadows /all /quiet\n"
        )
        result = run(tmp_upload(content), "drop.bat")
        matched = result.details["matched_pattern_codes"]
        assert "run_key" in matched
        assert "inhibit_recovery" in matched

    def test_encoded_blobs_are_flagged(self, tmp_upload):
        content = b"payload = '" + b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqaw==" * 2 + b"'\n"
        result = run(tmp_upload(content), "loader.py")
        assert "file_encoded_blobs" in codes(result)

    def test_benign_text_produces_no_suspicious_string_findings(self, tmp_upload):
        result = run(tmp_upload(TEXT), "notes.txt")
        assert "file_no_suspicious_strings" in codes(result)
        assert result.details["matched_pattern_codes"] == []


class TestEntropy:
    def test_repetitive_content_has_low_entropy(self):
        assert file_analyzer.shannon_entropy(b"A" * 5000) < 0.1

    def test_uniform_random_content_approaches_eight_bits(self):
        data = bytes(range(256)) * 40
        assert file_analyzer.shannon_entropy(data) > 7.9

    def test_high_entropy_binary_is_flagged(self, tmp_upload):
        result = run(tmp_upload(b"MZ" + bytes(range(256)) * 40), "packed.exe")
        assert "file_high_entropy" in codes(result)


class TestFilenameSanitization:
    @pytest.mark.parametrize(
        ("raw", "must_not_contain"),
        [
            ("../../etc/passwd", "/"),
            ("..\\..\\windows\\system32\\cmd.exe", "\\"),
            ("....//....//secret.txt", "/"),
        ],
    )
    def test_path_traversal_is_stripped(self, raw, must_not_contain):
        cleaned = storage.sanitize_filename(raw)
        assert must_not_contain not in cleaned
        assert ".." not in cleaned

    def test_control_characters_are_removed(self):
        assert "\x00" not in storage.sanitize_filename("bad\x00name.txt")
        assert "\n" not in storage.sanitize_filename("bad\nname.txt")

    def test_windows_reserved_names_are_defused(self):
        assert storage.sanitize_filename("CON.txt").lower() != "con.txt"

    def test_empty_and_dotty_names_get_a_fallback(self):
        assert storage.sanitize_filename("") == "unnamed"
        assert storage.sanitize_filename("...") == "unnamed"

    def test_length_is_bounded_and_extension_preserved(self):
        cleaned = storage.sanitize_filename("a" * 400 + ".txt")
        assert len(cleaned) <= storage.MAX_FILENAME_LENGTH
        assert cleaned.endswith(".txt")

    def test_ordinary_names_survive_intact(self):
        assert storage.sanitize_filename("quarterly-report_v2.final.pdf") == (
            "quarterly-report_v2.final.pdf"
        )


class TestQuarantineStorage:
    def test_stored_file_lands_inside_the_quarantine_root(self):
        path, size = storage.store_stream([b"hello"])
        try:
            assert path.parent.resolve() == storage.quarantine_root().resolve()
            assert size == 5
        finally:
            storage.discard(path)

    def test_storage_name_is_randomised_and_unrelated_to_the_upload(self):
        first, _ = storage.store_stream([b"a"])
        second, _ = storage.store_stream([b"a"])
        try:
            assert first.name != second.name
            assert first.suffix == ".bin"
        finally:
            storage.discard(first)
            storage.discard(second)

    def test_oversized_upload_is_rejected_mid_stream(self):
        chunks = [b"X" * 1024 for _ in range(100)]
        with pytest.raises(PayloadTooLarge):
            storage.store_stream(chunks, max_bytes=4096)

    def test_rejected_upload_leaves_nothing_on_disk(self):
        before = set(storage.quarantine_root().iterdir())
        with pytest.raises(PayloadTooLarge):
            storage.store_stream([b"X" * 8192], max_bytes=1024)
        assert set(storage.quarantine_root().iterdir()) == before

    def test_discard_is_idempotent(self, tmp_path):
        missing = tmp_path / "never-existed.bin"
        storage.discard(missing)  # must not raise
        storage.discard(None)
