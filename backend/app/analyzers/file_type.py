"""Content-based file type identification via magic bytes.

Implemented directly rather than via libmagic so the container needs no native
dependency, and -- more importantly -- so the identification logic is visible
and testable. Identification is *content* based on purpose: the declared
Content-Type and the file extension are both attacker-controlled, and the gap
between what a file claims to be and what it actually is is itself a finding.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FileType:
    identifier: str
    description: str
    mime: str
    category: str  # executable | document | archive | image | text | data
    # Executable formats are never run, only described. The flag exists so the
    # risk engine can weight "this is code" without re-parsing the description.
    is_executable_format: bool = False


UNKNOWN_BINARY = FileType("unknown", "Unknown binary data", "application/octet-stream", "data")
PLAIN_TEXT = FileType("text", "Plain text", "text/plain", "text")

# (offset, signature bytes, FileType)
_SIGNATURES: list[tuple[int, bytes, FileType]] = [
    (0, b"MZ", FileType("pe", "Windows PE executable (MZ)", "application/vnd.microsoft.portable-executable", "executable", True)),
    (0, b"\x7fELF", FileType("elf", "ELF executable / shared object", "application/x-elf", "executable", True)),
    # Java .class and Mach-O fat binaries share the CAFEBABE magic; the class
    # file's next two fields (minor version, high byte of major) are zero,
    # which disambiguates in practice. Checked first because it is stricter.
    (0, b"\xca\xfe\xba\xbe\x00\x00\x00", FileType("class", "Java class file", "application/java-vm", "executable", True)),
    (0, b"\xca\xfe\xba\xbe", FileType("macho_fat", "Mach-O universal binary", "application/x-mach-binary", "executable", True)),
    (0, b"\xcf\xfa\xed\xfe", FileType("macho64", "Mach-O 64-bit executable", "application/x-mach-binary", "executable", True)),
    (0, b"\xce\xfa\xed\xfe", FileType("macho32", "Mach-O 32-bit executable", "application/x-mach-binary", "executable", True)),
    (0, b"%PDF-", FileType("pdf", "PDF document", "application/pdf", "document")),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", FileType("ole2", "Legacy OLE2 Office document", "application/x-ole-storage", "document")),
    (0, b"PK\x03\x04", FileType("zip", "ZIP archive (or OOXML/JAR container)", "application/zip", "archive")),
    (0, b"Rar!\x1a\x07", FileType("rar", "RAR archive", "application/vnd.rar", "archive")),
    (0, b"7z\xbc\xaf\x27\x1c", FileType("7z", "7-Zip archive", "application/x-7z-compressed", "archive")),
    (0, b"\x1f\x8b", FileType("gzip", "GZIP compressed data", "application/gzip", "archive")),
    (0, b"BZh", FileType("bzip2", "BZIP2 compressed data", "application/x-bzip2", "archive")),
    (0, b"\xfd7zXZ\x00", FileType("xz", "XZ compressed data", "application/x-xz", "archive")),
    (0, b"\x89PNG\r\n\x1a\n", FileType("png", "PNG image", "image/png", "image")),
    (0, b"\xff\xd8\xff", FileType("jpeg", "JPEG image", "image/jpeg", "image")),
    (0, b"GIF87a", FileType("gif", "GIF image", "image/gif", "image")),
    (0, b"GIF89a", FileType("gif", "GIF image", "image/gif", "image")),
    (0, b"BM", FileType("bmp", "BMP image", "image/bmp", "image")),
    (0, b"II*\x00", FileType("tiff", "TIFF image", "image/tiff", "image")),
    (0, b"MM\x00*", FileType("tiff", "TIFF image", "image/tiff", "image")),
    (0, b"\x00\x00\x01\x00", FileType("ico", "Windows icon", "image/x-icon", "image")),
    (0, b"OggS", FileType("ogg", "OGG media container", "application/ogg", "data")),
    (0, b"ID3", FileType("mp3", "MP3 audio (ID3)", "audio/mpeg", "data")),
    (0, b"SQLite format 3\x00", FileType("sqlite", "SQLite 3 database", "application/vnd.sqlite3", "data")),
    (0, b"#!", FileType("script", "Script with shebang interpreter line", "text/x-script", "text", True)),
    (0, b"{\\rtf", FileType("rtf", "Rich Text Format document", "application/rtf", "document")),
    (0, b"\xef\xbb\xbf", PLAIN_TEXT),  # UTF-8 BOM
    (4, b"ftyp", FileType("mp4", "ISO base media container (MP4/MOV)", "video/mp4", "data")),
]

# Text formats worth naming specifically once we know the file is textual.
_TEXT_HINTS: list[tuple[bytes, FileType]] = [
    (b"<?xml", FileType("xml", "XML document", "text/xml", "text")),
    (b"<!doctype html", FileType("html", "HTML document", "text/html", "text")),
    (b"<html", FileType("html", "HTML document", "text/html", "text")),
    (b"<?php", FileType("php", "PHP source", "text/x-php", "text", True)),
    (b"@echo off", FileType("batch", "Windows batch script", "text/x-msdos-batch", "text", True)),
    (b"function ", FileType("script_text", "Script source", "text/plain", "text", True)),
    (b"import ", FileType("script_text", "Script source", "text/plain", "text", True)),
]


def looks_textual(data: bytes) -> bool:
    """Heuristic used everywhere we must decide 'can I safely read this as text'.

    A NUL byte or a high proportion of non-printable bytes means binary. This
    matters for safety framing: we only ever *read* bytes, but string
    extraction on binary produces noise that inflates false positives.
    """
    if not data:
        return True
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(sample) >= 0.85


def identify(data: bytes) -> FileType:
    for offset, magic, file_type in _SIGNATURES:
        if data[offset : offset + len(magic)] == magic:
            if file_type is PLAIN_TEXT:
                break
            return file_type

    if looks_textual(data):
        head = data[:512].lstrip().lower()
        for prefix, file_type in _TEXT_HINTS:
            if head.startswith(prefix) or prefix in head:
                return file_type
        return PLAIN_TEXT

    return UNKNOWN_BINARY


def refine_zip(data: bytes) -> FileType:
    """Distinguish OOXML/JAR/APK from a plain ZIP by container member names.

    Reads the central-directory filenames as raw bytes; nothing is extracted or
    decompressed, so a zip bomb cannot be triggered here.
    """
    window = data[:65536]
    if b"word/document.xml" in window:
        return FileType("docx", "OOXML Word document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "document")
    if b"xl/workbook.xml" in window:
        return FileType("xlsx", "OOXML Excel workbook", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "document")
    if b"ppt/presentation.xml" in window:
        return FileType("pptx", "OOXML PowerPoint presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "document")
    if b"AndroidManifest.xml" in window:
        return FileType("apk", "Android application package", "application/vnd.android.package-archive", "archive", True)
    if b"META-INF/MANIFEST.MF" in window:
        return FileType("jar", "Java archive (JAR)", "application/java-archive", "archive", True)
    if b"mimetypeapplication/vnd.oasis.opendocument" in window:
        return FileType("odf", "OpenDocument file", "application/vnd.oasis.opendocument", "document")
    return FileType("zip", "ZIP archive", "application/zip", "archive")
