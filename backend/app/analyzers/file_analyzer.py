"""Static file analysis.

SAFETY CONTRACT -- read before changing anything in this module:

  * The file is opened read-only and treated as opaque bytes.
  * It is NEVER executed, never passed to a shell, never handed to an
    interpreter, never extracted, and never parsed by a format library that
    could act on embedded content (no macro engines, no PDF JS, no unzip).
  * Every operation here is either hashing, byte-pattern matching, or
    printable-run extraction.

AVAILABILITY IS PART OF THE CONTRACT
------------------------------------
"Cannot harm the host" is not only about execution. A sample that makes the
analyzer burn unbounded CPU takes the service down just as effectively as one
that runs code, and it needs no exploit to do it -- only a pathological byte
sequence. Three mechanisms bound that here:

  * every scan is capped in input size and in result count;
  * indicator extraction is linear by construction (see `extract.py`);
  * an `AnalysisBudget` deadline is threaded through every loop, so worst-case
    input yields a *truncated and clearly labelled* report instead of a hung
    worker.

The caller additionally runs this module in a worker thread (see
`services/analysis_service.py`), so even a slow analysis cannot stall the event
loop and take the rest of the API with it.

Anything that would violate the above belongs in a sandboxed detonation service
running on isolated infrastructure -- explicitly out of scope for this project.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from pathlib import Path

from ..core.config import settings
from ..models.enums import AnalysisStatus, IndicatorType, Severity
from . import file_type as ft
from .base import AnalyzerResult, Signal, ok, signal
from .extract import AnalysisBudget, extract_all
from .patterns import (
    ARCHIVE_EXTENSIONS,
    BASE64_RE,
    DOUBLE_EXTENSION_RE,
    HEX_BLOB_RE,
    RISKY_FILE_EXTENSIONS,
    SUSPICIOUS_CONTENT_PATTERNS,
)
from ..core.sanitize import defang_all, scrub, scrub_all

CATEGORY = "file"

HASH_CHUNK_BYTES = 1024 * 1024
MIN_STRING_LENGTH = 6
# Cap the text that gets pattern-matched. Hashing still covers the whole file;
# this bound applies only to the (much more expensive) content sweep.
MAX_TEXT_SCAN_BYTES = 1024 * 1024
# Entropy is a distribution estimate -- a sample is as good as the whole file
# and costs a fraction as much.
MAX_ENTROPY_SAMPLE_BYTES = 256 * 1024
PRINTABLE_RUN_RE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING_LENGTH)

HIGH_ENTROPY_THRESHOLD = 7.2  # bits/byte; packed or encrypted content


def compute_hashes(path: Path) -> dict[str, str]:
    """MD5, SHA-1 and SHA-256 in a single streaming pass.

    Streaming (rather than read-then-hash) keeps memory flat regardless of file
    size, which is what makes the 10 MB ceiling a policy choice rather than a
    memory constraint.
    """
    # usedforsecurity=False: MD5/SHA-1 are computed as *identifiers* for IOC
    # pivoting, not as a security control. The flag keeps this working on
    # FIPS-enabled hosts where those algorithms are otherwise blocked.
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_strings(
    data: bytes, *, limit: int | None = None, budget: AnalysisBudget | None = None
) -> list[str]:
    """Pull printable ASCII runs, the classic `strings(1)` primitive."""
    cap = limit if limit is not None else settings.max_strings_extracted
    found: list[str] = []
    for index, match in enumerate(PRINTABLE_RUN_RE.finditer(data[:MAX_TEXT_SCAN_BYTES])):
        if budget and index % 512 == 0 and budget.expired:
            break
        found.append(match.group().decode("ascii", errors="ignore").strip())
        if len(found) >= cap:
            break
    return found


def analyze(
    path: Path,
    original_filename: str,
    sanitized_filename: str,
    size: int,
    *,
    budget: AnalysisBudget | None = None,
) -> AnalyzerResult:
    budget = budget or AnalysisBudget(settings.file_analysis_timeout_seconds)

    # Hashing covers the whole file and is strictly linear, so it is never the
    # part that needs bounding.
    hashes = compute_hashes(path)

    with open(path, "rb") as handle:
        head = handle.read(MAX_TEXT_SCAN_BYTES)

    detected = ft.identify(head)
    if detected.identifier == "zip":
        detected = ft.refine_zip(head)

    entropy = round(shannon_entropy(head[:MAX_ENTROPY_SAMPLE_BYTES]), 3)
    textual = ft.looks_textual(head)

    signals: list[Signal] = [
        ok("file_hashed", "Cryptographic hashes computed",
           f"SHA-256 {hashes['sha256']}", CATEGORY),
        ok("file_not_executed", "Sample was not executed",
           "Analysis was entirely static: the file was read as bytes, hashed and "
           "pattern-matched. It was never run, extracted or parsed by a format "
           "handler.", CATEGORY),
    ]

    details: dict = {
        # Scrubbed: the client-supplied name reaches logs and the UI, and is
        # exactly where a bidi override would be planted.
        "original_filename": scrub(original_filename),
        "sanitized_filename": sanitized_filename,
        "size_bytes": size,
        "hashes": hashes,
        "detected_type": detected.identifier,
        "detected_type_description": detected.description,
        "detected_mime": detected.mime,
        "type_category": detected.category,
        "entropy": entropy,
        "is_textual": textual,
        "scanned_bytes": len(head),
        "fully_scanned": len(head) >= size,
        "storage": "Sample stored in quarantine outside the web root"
        + ("; deleted after analysis." if settings.delete_uploads_after_analysis else "."),
    }

    signals.extend(_filename_signals(sanitized_filename, detected, details))
    signals.extend(_content_type_signals(detected, entropy, size, details))

    if textual:
        text = head.decode("utf-8", errors="replace")
    else:
        strings = extract_strings(head, budget=budget)
        details["extracted_string_count"] = len(strings)
        # Scrubbed *and* capped: these are attacker-authored strings destined
        # for a browser, a log file and a database column.
        details["sample_strings"] = scrub_all(strings[:60])
        text = "\n".join(strings)

    signals.extend(_static_string_signals(text, details, budget))

    if size > len(head):
        signals.append(
            signal(
                "file_scan_window",
                f"Content sweep limited to the first {len(head) // 1024} KB",
                "Hashes cover the entire file. Pattern matching is capped so that a "
                "large sample cannot monopolise the analysis worker; content beyond "
                "the window was not inspected.",
                0,
                Severity.INFO,
                CATEGORY,
            )
        )

    status = AnalysisStatus.COMPLETED
    if budget.truncated:
        # Saying so is the whole point: a silently shortened sweep would let a
        # crafted sample suppress findings and look clean.
        status = AnalysisStatus.PARTIAL
        details["analysis_truncated"] = True
        signals.append(
            signal(
                "file_analysis_truncated",
                "Static analysis stopped at the time limit",
                f"Content inspection exceeded the {budget.seconds:g}s budget for this "
                "sample and was stopped early. Hashes and file type are complete; "
                "string and pattern findings may be incomplete. Treat the absence of "
                "further findings as inconclusive rather than clean.",
                0,
                Severity.INFO,
                CATEGORY,
            )
        )

    return AnalyzerResult(
        indicator=hashes["sha256"],
        indicator_display=sanitized_filename,
        indicator_type=IndicatorType.FILE,
        signals=signals,
        details=details,
        status=status,
        lookup_key=hashes["sha256"],
    )


# --------------------------------------------------------------------------
def _filename_signals(filename: str, detected: ft.FileType, details: dict) -> list[Signal]:
    out: list[Signal] = []
    lowered = filename.lower()
    extension = lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    details["extension"] = extension or None

    if extension in RISKY_FILE_EXTENSIONS:
        out.append(
            signal(
                "file_risky_extension",
                f"Executable/script extension (.{extension})",
                "The filename declares a directly runnable type. Delivery of such a "
                "file to an end user is the User Execution step of most intrusions.",
                15,
                Severity.MEDIUM,
                CATEGORY,
                ("T1204.002",),
            )
        )
    elif extension in ARCHIVE_EXTENSIONS:
        out.append(
            signal(
                "file_archive",
                f"Archive container (.{extension})",
                "Archives are commonly used to wrap executables past mail gateways. "
                "Contents were NOT extracted -- extraction is unsafe and out of scope.",
                5,
                Severity.LOW,
                CATEGORY,
            )
        )

    if DOUBLE_EXTENSION_RE.search(lowered):
        out.append(
            signal(
                "file_double_extension",
                "Double file extension",
                f"'{filename}' presents as a document but ends in an executable "
                "extension -- masquerading aimed at users whose file manager hides "
                "known extensions.",
                20,
                Severity.HIGH,
                CATEGORY,
                ("T1036", "T1204.002"),
            )
        )

    # Right-to-left override flips the displayed filename ("...cod.exe" shows
    # as "...exe.doc"). Its presence in a filename has no legitimate use here.
    if "‮" in filename or "%u202e" in lowered:
        out.append(
            signal(
                "file_rtlo",
                "Right-to-left override character in filename",
                "U+202E reverses how the remaining characters are displayed, hiding the "
                "true extension from the user.",
                25,
                Severity.HIGH,
                CATEGORY,
                ("T1036",),
            )
        )

    # Extension/content mismatch: the strongest cheap masquerading signal.
    declared_binary = extension in {"txt", "csv", "log", "md", "json", "pdf", "jpg", "jpeg", "png", "gif", "doc", "docx"}
    if declared_binary and detected.is_executable_format:
        out.append(
            signal(
                "file_type_mismatch",
                "File content does not match its extension",
                f"The extension '.{extension}' claims a document/image, but the magic "
                f"bytes identify {detected.description}.",
                25,
                Severity.HIGH,
                CATEGORY,
                ("T1036",),
            )
        )
    elif extension and _extension_conflicts(extension, detected):
        out.append(
            signal(
                "file_type_soft_mismatch",
                "Extension and detected type differ",
                f"Extension '.{extension}' vs detected {detected.description}. Often "
                "benign (renamed files, generic extensions) but worth confirming.",
                8,
                Severity.LOW,
                CATEGORY,
            )
        )
    else:
        out.append(
            ok("file_type_consistent", "Extension consistent with content",
               f"Detected {detected.description}.", CATEGORY)
        )
    return out


_EXTENSION_CATEGORY = {
    "txt": "text", "md": "text", "csv": "text", "log": "text", "json": "text",
    "xml": "text", "html": "text", "htm": "text", "js": "text", "py": "text",
    "ps1": "text", "sh": "text", "bat": "text", "yaml": "text", "yml": "text",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image",
    "bmp": "image", "tiff": "image", "ico": "image",
    "pdf": "document", "doc": "document", "docx": "document", "xls": "document",
    "xlsx": "document", "ppt": "document", "pptx": "document", "rtf": "document",
    "zip": "archive", "rar": "archive", "7z": "archive", "gz": "archive",
    "tar": "archive", "bz2": "archive", "xz": "archive", "jar": "archive",
    "exe": "executable", "dll": "executable", "so": "executable", "elf": "executable",
}


def _extension_conflicts(extension: str, detected: ft.FileType) -> bool:
    expected = _EXTENSION_CATEGORY.get(extension)
    if expected is None or detected.identifier == "unknown":
        return False
    return expected != detected.category


def _content_type_signals(detected: ft.FileType, entropy: float, size: int, details: dict) -> list[Signal]:
    out: list[Signal] = []

    if detected.is_executable_format and detected.category == "executable":
        out.append(
            signal(
                "file_executable_format",
                f"Executable binary format ({detected.description})",
                "The content is machine code or bytecode. This is a property of the "
                "file, not evidence of malice -- but it means the file can do "
                "something if a user runs it.",
                15,
                Severity.MEDIUM,
                CATEGORY,
                ("T1204.002",),
            )
        )

    if detected.identifier == "ole2":
        out.append(
            signal(
                "file_legacy_office",
                "Legacy OLE2 Office document",
                "Pre-2007 Office formats carry VBA macros in a binary stream and remain "
                "a common malicious-document vehicle. Macro streams were NOT parsed or "
                "executed here.",
                12,
                Severity.MEDIUM,
                CATEGORY,
                ("T1204.002",),
            )
        )

    if detected.identifier in {"docx", "xlsx", "pptx"}:
        out.append(
            ok("file_ooxml", f"{detected.description}",
               "Modern OOXML container. Macro-enabled variants (.docm/.xlsm) carry "
               "higher risk; container members were not extracted.", CATEGORY)
        )

    if entropy >= HIGH_ENTROPY_THRESHOLD and size > 2048:
        out.append(
            signal(
                "file_high_entropy",
                f"High entropy content (H={entropy} bits/byte)",
                "Near-random byte distribution indicates compressed, packed or "
                "encrypted data. Legitimate for archives and media; for an executable "
                "it usually means a packer was applied to resist static analysis.",
                15 if detected.category == "executable" else 5,
                Severity.MEDIUM if detected.category == "executable" else Severity.LOW,
                CATEGORY,
                ("T1027",),
            )
        )
    elif detected.category != "data":
        out.append(
            ok("file_entropy_normal", f"Entropy within expected range (H={entropy})",
               "No indication of packing or whole-file encryption.", CATEGORY)
        )

    if size == 0:
        out.append(
            signal("file_empty", "Empty file", "The upload contains zero bytes.",
                   0, Severity.INFO, CATEGORY)
        )
    return out


def _bounded_matches(
    regex: re.Pattern[str],
    text: str,
    *,
    cap: int,
    budget: AnalysisBudget,
    min_length: int = 0,
) -> list[str]:
    """Collect at most `cap` matches, stopping early if the budget runs out."""
    found: list[str] = []
    for index, match in enumerate(regex.finditer(text)):
        if index % 64 == 0 and budget.expired:
            break
        value = match.group()
        if len(value) < min_length:
            continue
        found.append(value)
        if len(found) >= cap:
            break
    return found


def _static_string_signals(
    text: str, details: dict, budget: AnalysisBudget | None = None
) -> list[Signal]:
    """Pattern sweep over extracted text. Matching only -- nothing is evaluated."""
    out: list[Signal] = []
    budget = budget or AnalysisBudget(settings.file_analysis_timeout_seconds)

    # Bounded, linear extraction. See extract.py for why this is not a set of
    # findall() calls over the whole blob.
    found = extract_all(text, limit=50, budget=budget)
    urls, ips = found.urls, found.ipv4
    emails, domains = found.emails, found.domains

    details["embedded_indicators"] = {
        # Stored defanged so nothing copied out of a report is directly
        # clickable or resolvable, and scrubbed so no invisible formatting
        # survives into the UI or the log.
        "urls": defang_all(scrub_all(urls)),
        "ipv4": defang_all(ips),
        "emails": scrub_all(emails),
        "domains": defang_all(domains),
        "windows_paths": scrub_all(found.windows_paths),
    }

    if urls:
        # Findings quote the defanged form: a description is rendered as text,
        # but it is also copied into tickets and chat clients that autolink.
        preview = ", ".join(defang_all(scrub_all(urls[:3])))
        out.append(
            signal(
                "file_embedded_urls",
                f"Embedded URL(s) found ({len(urls)})",
                f"The file references remote endpoints: {preview}"
                + ("..." if len(urls) > 3 else ""),
                10,
                Severity.MEDIUM,
                CATEGORY,
                ("T1071.001",),
            )
        )
    if ips:
        out.append(
            signal(
                "file_embedded_ips",
                f"Hardcoded IP address(es) found ({len(ips)})",
                "Hardcoded addresses bypass DNS and are typical of staging or C2 "
                "configuration: " + ", ".join(defang_all(ips[:3])),
                12,
                Severity.MEDIUM,
                CATEGORY,
                ("T1071.001",),
            )
        )

    # finditer with an early break rather than findall: a file that is one
    # enormous base64 blob should cost a bounded amount of work, not build a
    # list proportional to its size.
    b64_hits = _bounded_matches(BASE64_RE, text, cap=20, budget=budget, min_length=40)
    if b64_hits:
        details["base64_candidates"] = len(b64_hits)
        out.append(
            signal(
                "file_encoded_blobs",
                f"Encoded-looking blob(s) ({len(b64_hits)})",
                "Long base64-like runs suggest embedded payloads or obfuscated "
                "configuration. Blobs were NOT decoded or executed.",
                15,
                Severity.MEDIUM,
                CATEGORY,
                ("T1027", "T1140"),
            )
        )

    hex_hits = _bounded_matches(HEX_BLOB_RE, text, cap=20, budget=budget)
    if hex_hits:
        details["hex_blob_candidates"] = len(hex_hits)
        out.append(
            signal(
                "file_hex_blobs",
                f"Long hexadecimal blob(s) ({len(hex_hits)})",
                "Hex-encoded byte arrays are a common way to embed shellcode or "
                "configuration inside otherwise readable source.",
                12,
                Severity.MEDIUM,
                CATEGORY,
                ("T1027",),
            )
        )

    matched_codes: list[str] = []
    for regex, code, title, points, mitre_ids in SUSPICIOUS_CONTENT_PATTERNS:
        # Checked between patterns, not inside them: `search` is atomic from
        # here, so this is the finest granularity available without rewriting
        # every pattern into a streaming matcher.
        if budget.expired:
            break
        match = regex.search(text)
        if not match:
            continue
        matched_codes.append(code)
        # Scrubbed: the excerpt is raw sample content quoted back into a
        # report, a log line and a database row.
        excerpt = scrub(match.group()[:80], max_length=80)
        out.append(
            signal(
                f"file_pattern_{code}",
                title,
                f"Matched on: '{excerpt}'. Presence of this string means the capability "
                "is referenced in the file's content; it is not proof the technique ran.",
                points,
                Severity.HIGH if points >= 20 else Severity.MEDIUM,
                CATEGORY,
                mitre_ids,
            )
        )

    details["matched_pattern_codes"] = matched_codes

    if not matched_codes and not urls and not ips and not b64_hits:
        out.append(
            ok("file_no_suspicious_strings", "No suspicious strings detected",
               "Static string analysis found no known-suspicious commands, encoded "
               "blobs or embedded network indicators.", CATEGORY)
        )
    return out
