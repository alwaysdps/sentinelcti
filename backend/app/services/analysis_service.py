"""Analysis orchestration.

One pipeline, five indicator types:

    validate -> analyze (signals) -> enrich (providers) -> score -> persist

Keeping orchestration here rather than in the routes means the HTTP layer stays
a thin adapter, and the same pipeline is reusable from the seed script and the
tests without a running server.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..analyzers import domain_analyzer, file_analyzer, hash_analyzer, ip_analyzer, mitre, url_analyzer
from ..analyzers.base import AnalyzerResult, Signal, signal
from ..analyzers.extract import AnalysisBudget
from ..core.sanitize import scrub, scrub_structure
from ..core.config import settings
from ..core.errors import NotFoundError
from ..models.analysis import Analysis
from ..models.enums import AnalysisStatus, ProviderResult, Severity
from ..providers import registry
from ..providers.base import ProviderLookup
from . import query_service, storage
from .risk_engine import assess

REFERENCE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1: unambiguous when read aloud


def new_reference() -> str:
    return "SC-" + "".join(secrets.choice(REFERENCE_ALPHABET) for _ in range(6))


# --------------------------------------------------------------------------
# Provider enrichment -> signals
# --------------------------------------------------------------------------
_PROVIDER_SEVERITY = {
    ProviderResult.MALICIOUS: Severity.HIGH,
    ProviderResult.SUSPICIOUS: Severity.MEDIUM,
    ProviderResult.CLEAN: Severity.PASS,
    ProviderResult.UNKNOWN: Severity.INFO,
    ProviderResult.ERROR: Severity.INFO,
}

# A provider naming an indicator is a positive identification, not a heuristic
# prior, so it sets a minimum verdict rather than merely adding points. Without
# this a known-malicious hash would score in the Low Risk band, because a bare
# hash offers nothing else to accumulate points from.
_PROVIDER_SCORE_FLOOR = {
    ProviderResult.MALICIOUS: 70,   # bottom of the High Risk band
    ProviderResult.SUSPICIOUS: 50,  # bottom of the Suspicious band
}


def provider_signals(lookups: list[ProviderLookup]) -> list[Signal]:
    out: list[Signal] = []
    for lookup in lookups:
        if lookup.result is ProviderResult.ERROR:
            out.append(
                signal(
                    f"provider_{lookup.provider.lower().replace(' ', '_')}_error",
                    f"{lookup.provider}: unavailable",
                    lookup.detail,
                    0,
                    Severity.INFO,
                    "intelligence",
                )
            )
            continue
        out.append(
            signal(
                f"provider_{lookup.provider.lower().replace(' ', '_')}_{lookup.result.value}",
                f"{lookup.provider}: {lookup.result.value}",
                lookup.detail,
                lookup.score_contribution,
                _PROVIDER_SEVERITY[lookup.result],
                "intelligence",
                score_floor=_PROVIDER_SCORE_FLOOR.get(lookup.result, 0),
            )
        )
    return out


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------
async def run_pipeline(
    db: Session,
    result: AnalyzerResult,
    *,
    is_demo: bool = False,
    owner_key: str | None = None,
) -> Analysis:
    started = time.perf_counter()

    lookups = await registry.lookup_all(result.indicator_type, result.lookup_key)
    all_signals = result.signals + provider_signals(lookups)

    assessment = assess(all_signals)
    status = result.status
    if any(l.result is ProviderResult.ERROR for l in lookups) and status is AnalysisStatus.COMPLETED:
        # The analysis is still valid, but the operator should know enrichment
        # was incomplete rather than assume full coverage.
        status = AnalysisStatus.PARTIAL

    technique_ids = [tid for s in all_signals for tid in s.mitre]
    duration = time.perf_counter() - started

    # Single neutralisation point for every indicator type. Analyzers quote the
    # submitted value back into titles, descriptions and technical details, so
    # scrubbing here -- rather than in each analyzer -- means a bidi override or
    # control character cannot reach the report, the log or the database from
    # ANY analyzer, including ones added later. The file analyzer also scrubs
    # its own extracted strings; scrub is idempotent, so that is harmless.
    record = Analysis(
        reference=new_reference(),
        indicator_type=result.indicator_type,
        indicator=scrub(result.indicator, max_length=2048),
        indicator_display=scrub(result.indicator_display, max_length=255),
        risk_score=assessment.score,
        verdict=assessment.verdict,
        status=status,
        findings=scrub_structure([_finding_dict(s) for s in all_signals]),
        details=scrub_structure({**result.details, "scoring": assessment.as_dict()}),
        provider_results=scrub_structure([l.as_dict() for l in lookups]),
        mitre_techniques=mitre.resolve(technique_ids),
        duration_seconds=round(duration, 4),
        is_demo=is_demo,
        owner_key=owner_key,
    )

    _persist_with_unique_reference(db, record)
    return record


def _persist_with_unique_reference(db: Session, record: Analysis, attempts: int = 5) -> None:
    """Commit, regenerating the reference if the random id happens to collide.

    32^6 keeps collisions vanishingly rare, but "rare" is not "impossible" and
    the column is UNIQUE -- so retry rather than fail a real analysis.
    """
    for attempt in range(attempts):
        try:
            db.add(record)
            db.commit()
            db.refresh(record)
            return
        except IntegrityError:
            db.rollback()
            if attempt == attempts - 1:
                raise
            record.reference = new_reference()


def _finding_dict(s: Signal) -> dict:
    return {
        "code": s.code,
        "title": s.title,
        "description": s.description,
        "points": s.points,
        "severity": s.severity.value,
        "category": s.category,
        "mitre": list(s.mitre),
    }


# --- Entry points per indicator type --------------------------------------
async def analyze_url(
    db: Session, value: str, *, is_demo: bool = False, owner_key: str | None = None
) -> Analysis:
    return await run_pipeline(db, url_analyzer.analyze(value), is_demo=is_demo, owner_key=owner_key)


async def analyze_domain(
    db: Session, value: str, *, is_demo: bool = False, owner_key: str | None = None
) -> Analysis:
    return await run_pipeline(db, domain_analyzer.analyze(value), is_demo=is_demo, owner_key=owner_key)


async def analyze_ip(
    db: Session, value: str, *, is_demo: bool = False, owner_key: str | None = None
) -> Analysis:
    return await run_pipeline(db, ip_analyzer.analyze(value), is_demo=is_demo, owner_key=owner_key)


async def analyze_hash(
    db: Session, value: str, *, is_demo: bool = False, owner_key: str | None = None
) -> Analysis:
    return await run_pipeline(db, hash_analyzer.analyze(value), is_demo=is_demo, owner_key=owner_key)


# Bounds how many samples are being inspected at once. Each analysis holds a
# worker thread and up to ~1 MB of scan buffer, so without this a burst of
# uploads would exhaust the threadpool and starve every other endpoint.
_file_analysis_slots = asyncio.Semaphore(settings.max_concurrent_file_analyses)


async def analyze_file(
    db: Session,
    stored_path: Path,
    original_filename: str,
    size: int,
    *,
    is_demo: bool = False,
    owner_key: str | None = None,
) -> Analysis:
    """Analyse an already-quarantined upload, then remove the bytes.

    Two things are load-bearing here.

    **The `finally` block**: the sample is deleted whether the analysis
    succeeded, timed out or blew up, so a crash can never leave hostile bytes
    sitting on disk.

    **The thread offload**: static analysis is CPU-bound work over
    attacker-controlled input. Running it inline on the event loop -- as this
    did originally -- means one slow sample stalls *every* concurrent request,
    turning a single crafted upload into a full API outage. `to_thread` keeps
    the loop free; the analyzer's own cooperative deadline is what bounds the
    thread, since a Python thread cannot be cancelled from outside.
    """
    sanitized = storage.sanitize_filename(original_filename)
    try:
        async with _file_analysis_slots:
            budget = AnalysisBudget(settings.file_analysis_timeout_seconds)
            result = await asyncio.to_thread(
                file_analyzer.analyze,
                stored_path,
                original_filename,
                sanitized,
                size,
                budget=budget,
            )
        return await run_pipeline(db, result, is_demo=is_demo, owner_key=owner_key)
    finally:
        if settings.delete_uploads_after_analysis:
            storage.discard(stored_path)


# --------------------------------------------------------------------------
# Queries
# --------------------------------------------------------------------------
def get_by_reference_or_id(
    db: Session, identifier: str, *, owner_key: str | None = None
) -> Analysis:
    """Fetch by numeric id or SC- reference, scoped to the caller's workspace.

    Scoping matters here as much as in the listing: references are short, and
    an unscoped lookup would let anyone read another workspace's report by
    guessing or sharing one. A row outside the caller's scope is reported as
    "not found" rather than "forbidden" -- the distinction would itself confirm
    that a given reference exists.
    """
    scope = query_service.visible_to(owner_key)
    stmt = select(Analysis).where(Analysis.reference == identifier.upper(), scope)
    record = db.execute(stmt).scalar_one_or_none()
    if record is None and identifier.isdigit():
        record = db.execute(
            select(Analysis).where(Analysis.id == int(identifier), scope)
        ).scalar_one_or_none()
    if record is None:
        raise NotFoundError(f"No analysis found for '{identifier}'.")
    return record


def delete_analysis(db: Session, identifier: str, *, owner_key: str | None = None) -> None:
    """Delete one of the caller's own analyses.

    Ownership is the authorisation: you may remove what you created, and
    nothing else. Shared demo rows belong to no workspace, so they are
    permanently read-only -- which is what keeps a first-time visitor's
    dashboard from being emptied by a passer-by.
    """
    record = get_by_reference_or_id(db, identifier, owner_key=owner_key)
    if record.is_demo or record.owner_key is None or record.owner_key != owner_key:
        raise NotFoundError(f"No analysis found for '{identifier}'.")
    db.execute(delete(Analysis).where(Analysis.id == record.id))
    db.commit()
