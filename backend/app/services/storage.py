"""Quarantine storage for uploaded samples.

Threat model for this module, stated explicitly because every rule below exists
to close one of these:

1. Path traversal  -- an upload named "../../app/main.py" must not overwrite
   anything. Solved by never using the client's name on disk at all: storage
   names are random, and the resolved path is asserted to sit inside the
   quarantine root before any write.
2. Re-serving      -- a stored payload must never be reachable over HTTP. The
   quarantine directory lives outside every static mount, and no route ever
   returns file bytes.
3. Execution       -- files are opened in binary read mode and hashed. Nothing
   in this codebase passes an upload to a shell, an interpreter, an archive
   extractor, or a parser that would honour embedded content.
4. Disk exhaustion -- writes stream with a hard byte ceiling and abort the
   moment it is exceeded, rather than trusting Content-Length.
"""

from __future__ import annotations

import os
import re
import secrets
import unicodedata
from pathlib import Path

from ..core.config import settings
from ..core.errors import CapacityExceeded, PayloadTooLarge

# Anything outside this set is replaced. Note that "." is allowed but runs of
# dots are collapsed, so "..%2f" style constructions cannot survive.
_SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")
_DOT_RUN_RE = re.compile(r"\.{2,}")

# Reserved device names on Windows; a file called "con.txt" is not writable and
# historically has been a source of odd failures.
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

MAX_FILENAME_LENGTH = 120


def sanitize_filename(raw: str) -> str:
    """Return a filename safe to *display and log*, never used as a disk path.

    Even the sanitised value is only metadata. The on-disk name comes from
    `secrets.token_hex`, so a sanitiser bug cannot become a write primitive.
    """
    if not raw:
        return "unnamed"

    # Strip any directory component in either separator style, plus NT stream
    # syntax ("file.txt:evil.exe").
    candidate = raw.replace("\\", "/").split("/")[-1]
    candidate = candidate.split(":")[-1] if os.name == "nt" else candidate
    candidate = unicodedata.normalize("NFKC", candidate)
    candidate = "".join(ch for ch in candidate if ch.isprintable() and ord(ch) > 31)
    candidate = _SAFE_CHARS_RE.sub("_", candidate)
    candidate = _DOT_RUN_RE.sub(".", candidate).strip(". _")

    if not candidate:
        return "unnamed"

    stem, dot, suffix = candidate.partition(".")
    if stem.lower() in _WINDOWS_RESERVED:
        stem = f"{stem}_file"
        candidate = f"{stem}{dot}{suffix}"

    if len(candidate) > MAX_FILENAME_LENGTH:
        stem, dot, suffix = candidate.rpartition(".")
        if dot and len(suffix) <= 10:
            keep = MAX_FILENAME_LENGTH - len(suffix) - 1
            candidate = f"{stem[:keep]}.{suffix}"
        else:
            candidate = candidate[:MAX_FILENAME_LENGTH]

    return candidate or "unnamed"


def quarantine_root() -> Path:
    root = settings.upload_dir
    root.mkdir(parents=True, exist_ok=True)
    return root


def _new_storage_path() -> Path:
    root = quarantine_root().resolve()
    # No extension: the stored object is inert data, and giving it an extension
    # invites some other tool to treat it as its type.
    path = (root / f"{secrets.token_hex(16)}.bin").resolve()
    # Defence in depth -- the name is generated, but assert containment anyway.
    if root not in path.parents:
        raise RuntimeError("Refusing to write outside the quarantine directory.")
    return path


def quarantine_usage_bytes() -> int:
    """Total bytes currently resident in quarantine."""
    total = 0
    try:
        for entry in quarantine_root().iterdir():
            try:
                if entry.is_file():
                    total += entry.stat().st_size
            except OSError:
                # A concurrent analysis deleting its own sample mid-scan is
                # normal, not an error.
                continue
    except OSError:  # pragma: no cover - directory vanished under us
        return 0
    return total


def assert_capacity(incoming_bytes: int | None = None) -> None:
    """Refuse a new upload when quarantine is already near its ceiling.

    Samples are deleted immediately after analysis, so this only trips under
    concurrent load. Without it, a burst of parallel uploads could fill the
    disk -- which takes down the database and the logs along with the API.
    """
    budget = settings.max_quarantine_bytes
    projected = quarantine_usage_bytes() + (incoming_bytes or settings.max_upload_bytes)
    if projected > budget:
        raise CapacityExceeded(
            "Analysis storage is at capacity. Retry in a moment.",
            details={"quarantine_budget_bytes": budget},
        )


def store_stream(chunks, *, max_bytes: int | None = None) -> tuple[Path, int]:
    """Persist an upload, enforcing the size ceiling as bytes arrive.

    Returns (path, size). Raises PayloadTooLarge -- after deleting the partial
    file -- as soon as the limit is crossed.
    """
    limit = max_bytes if max_bytes is not None else settings.max_upload_bytes
    assert_capacity()
    path = _new_storage_path()
    written = 0

    try:
        # 0o600: readable only by the service account that will hash it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            for chunk in chunks:
                if not chunk:
                    continue
                written += len(chunk)
                if written > limit:
                    raise PayloadTooLarge(
                        f"File exceeds the {limit // (1024 * 1024)} MB upload limit.",
                        details={"limit_bytes": limit},
                    )
                handle.write(chunk)
    except BaseException:
        discard(path)
        raise

    return path, written


def discard(path: Path | None) -> None:
    """Best-effort removal. Failure to delete must never fail an analysis."""
    if path is None:
        return
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:  # pragma: no cover - platform/permission dependent
        pass
