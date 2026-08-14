"""Domain vocabulary shared by models, schemas and analyzers.

These are plain str-enums so they serialise directly to JSON and store as
readable text in the database -- readable rows matter when the database is
itself an investigative artefact.
"""

from __future__ import annotations

from enum import StrEnum


class IndicatorType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"
    FILE = "file"


class Verdict(StrEnum):
    CLEAN = "clean"
    LOW_RISK = "low_risk"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


class AnalysisStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"  # analysis finished, but an optional enrichment failed
    FAILED = "failed"


class Severity(StrEnum):
    """How a single finding should be presented, independent of its points."""

    PASS = "pass"  # a positive/benign observation
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ProviderResult(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    ERROR = "error"
