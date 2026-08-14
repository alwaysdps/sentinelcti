"""File-hash analysis.

A hash carries no intrinsic structure to reason about -- it is an opaque
identifier. So this analyzer does two things: it validates and classifies the
hash, and it delegates the actual question ("is this known bad?") to the
threat-intelligence provider layer. Algorithm strength is reported because an
MD5-only IOC is weaker evidence than a SHA-256 one: MD5 and SHA-1 both have
practical collision attacks, so two different files can share a hash.
"""

from __future__ import annotations

from ..core.errors import ValidationFailure
from ..models.enums import IndicatorType, Severity
from .base import AnalyzerResult, Signal, ok, signal
from .patterns import HASH_LENGTHS, HEX_ONLY_RE

CATEGORY = "hash"

# Hashes of zero-length and other trivially-empty inputs. Submitting one almost
# always means a truncated or failed acquisition upstream, so we say so.
EMPTY_FILE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "MD5 of an empty (0-byte) file",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "SHA-1 of an empty (0-byte) file",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        "SHA-256 of an empty (0-byte) file",
}


def identify_hash_type(value: str) -> str | None:
    """Return 'MD5' | 'SHA-1' | 'SHA-256', or None if it is not a known hash."""
    candidate = value.strip()
    if not HEX_ONLY_RE.match(candidate):
        return None
    return HASH_LENGTHS.get(len(candidate))


def analyze(raw_hash: str) -> AnalyzerResult:
    value = raw_hash.strip().lower()
    if not value:
        raise ValidationFailure("A file hash is required.")

    if not HEX_ONLY_RE.match(value):
        raise ValidationFailure(
            "Hash must contain hexadecimal characters only (0-9, a-f)."
        )

    algorithm = HASH_LENGTHS.get(len(value))
    if algorithm is None:
        supported = ", ".join(f"{name} ({length} chars)" for length, name in sorted(HASH_LENGTHS.items()))
        raise ValidationFailure(
            f"Unrecognised hash length ({len(value)} characters). Supported: {supported}."
        )

    signals: list[Signal] = [
        ok("hash_valid", f"Valid {algorithm} hash",
           f"Input is a well-formed {algorithm} digest ({len(value)} hex characters).",
           CATEGORY)
    ]
    details: dict = {
        "hash": value,
        "algorithm": algorithm,
        "length": len(value),
        "bit_length": len(value) * 4,
    }

    if algorithm in {"MD5", "SHA-1"}:
        details["collision_resistant"] = False
        signals.append(
            signal(
                "hash_weak_algorithm",
                f"{algorithm} is not collision resistant",
                f"{algorithm} has practical collision attacks, so this digest identifies "
                "a file only weakly. Prefer SHA-256 when pivoting or blocking on it.",
                0,
                Severity.INFO,
                CATEGORY,
            )
        )
    else:
        details["collision_resistant"] = True
        signals.append(
            ok("hash_strong_algorithm", "SHA-256 is collision resistant",
               "The digest is a reliable unique identifier for the file content.",
               CATEGORY)
        )

    if value in EMPTY_FILE_HASHES:
        details["well_known"] = EMPTY_FILE_HASHES[value]
        signals.append(
            signal(
                "hash_empty_file",
                "Digest of an empty file",
                f"{EMPTY_FILE_HASHES[value]}. This usually indicates a truncated or "
                "failed sample acquisition rather than a real sample.",
                0,
                Severity.INFO,
                CATEGORY,
            )
        )

    return AnalyzerResult(
        indicator=value,
        indicator_display=value,
        indicator_type=IndicatorType.HASH,
        signals=signals,
        details=details,
        lookup_key=value,
    )
