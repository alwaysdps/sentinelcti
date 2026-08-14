"""Hash analyzer behaviour."""

from __future__ import annotations

import hashlib

import pytest

from app.analyzers import hash_analyzer
from app.core.errors import ValidationFailure
from app.models.enums import IndicatorType

MD5 = hashlib.md5(b"sentinelcti", usedforsecurity=False).hexdigest()
SHA1 = hashlib.sha1(b"sentinelcti", usedforsecurity=False).hexdigest()
SHA256 = hashlib.sha256(b"sentinelcti").hexdigest()


class TestIdentification:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [(MD5, "MD5"), (SHA1, "SHA-1"), (SHA256, "SHA-256")],
    )
    def test_algorithm_is_identified_from_length(self, value, expected):
        assert hash_analyzer.identify_hash_type(value) == expected
        result = hash_analyzer.analyze(value)
        assert result.details["algorithm"] == expected
        assert result.indicator_type is IndicatorType.HASH

    def test_uppercase_input_is_normalised(self):
        result = hash_analyzer.analyze(SHA256.upper())
        assert result.indicator == SHA256

    def test_surrounding_whitespace_is_tolerated(self):
        result = hash_analyzer.analyze(f"  {MD5}  ")
        assert result.indicator == MD5

    @pytest.mark.parametrize("bad", ["", "   ", "not-a-hash", "zzzz" * 8, MD5[:-1], SHA256 + "ab"])
    def test_invalid_hashes_are_rejected(self, bad):
        with pytest.raises(ValidationFailure):
            hash_analyzer.analyze(bad)

    def test_non_hex_characters_are_rejected_with_a_clear_message(self):
        with pytest.raises(ValidationFailure) as exc:
            hash_analyzer.analyze("g" * 32)
        assert "hexadecimal" in str(exc.value).lower()

    def test_unknown_length_is_not_identified(self):
        assert hash_analyzer.identify_hash_type("ab" * 24) is None


class TestAlgorithmStrength:
    @pytest.mark.parametrize("value", [MD5, SHA1])
    def test_weak_algorithms_are_annotated_without_scoring(self, value):
        result = hash_analyzer.analyze(value)
        weak = next(s for s in result.signals if s.code == "hash_weak_algorithm")
        # A weak algorithm is a caveat about evidence quality, not a risk factor.
        assert weak.points == 0
        assert result.details["collision_resistant"] is False

    def test_sha256_is_marked_collision_resistant(self):
        result = hash_analyzer.analyze(SHA256)
        assert result.details["collision_resistant"] is True


class TestWellKnownHashes:
    def test_empty_file_digest_is_recognised(self):
        empty = hashlib.sha256(b"").hexdigest()
        result = hash_analyzer.analyze(empty)
        assert "hash_empty_file" in {s.code for s in result.signals}

    def test_eicar_hashes_in_the_local_dataset_are_correct(self):
        """Guards the hard-coded EICAR digests in the local provider dataset."""
        from app.providers.local_provider import _HASHES

        eicar = (
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
            + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            + r"!$H+H*"
        ).encode()
        assert hashlib.md5(eicar, usedforsecurity=False).hexdigest() in _HASHES
        assert hashlib.sha1(eicar, usedforsecurity=False).hexdigest() in _HASHES
        assert hashlib.sha256(eicar).hexdigest() in _HASHES


class TestLookupKey:
    def test_lookup_key_is_the_normalised_digest(self):
        result = hash_analyzer.analyze(SHA256.upper())
        assert result.lookup_key == SHA256
