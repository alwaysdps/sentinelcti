"""Submission endpoints.

Routes are intentionally thin: validate (Pydantic), delegate (service), return
(schema). All analysis logic sits behind `services.analysis_service`.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, File, Request, UploadFile, status
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.errors import ValidationFailure
from ..core.owner import resolve_owner_key
from ..database import get_db
from ..schemas.analysis import (
    AnalysisDetail,
    DomainAnalysisRequest,
    HashAnalysisRequest,
    IPAnalysisRequest,
    URLAnalysisRequest,
)
from ..services import analysis_service, storage

router = APIRouter(prefix="/api/analyze", tags=["Analysis"])

_RESPONSES = {
    422: {"description": "The indicator failed validation."},
    429: {"description": "Rate limit exceeded."},
}


@router.post(
    "/url",
    response_model=AnalysisDetail,
    status_code=status.HTTP_201_CREATED,
    responses=_RESPONSES,
    summary="Analyse a URL",
    description=(
        "Performs **static** URL analysis: syntax, scheme, host classification, "
        "punycode, subdomain depth, brand impersonation, encoding tricks and "
        "payload extensions.\n\n"
        "The URL is never requested. Nothing is fetched, crawled or resolved from "
        "the URL itself, so submitting a live phishing link does not notify its "
        "operator."
    ),
)
async def analyze_url(
    request: Request, payload: URLAnalysisRequest, db: Session = Depends(get_db)
) -> AnalysisDetail:
    record = await analysis_service.analyze_url(
        db, payload.url, owner_key=resolve_owner_key(request)
    )
    return AnalysisDetail.model_validate(record, from_attributes=True)


@router.post(
    "/domain",
    response_model=AnalysisDetail,
    status_code=status.HTTP_201_CREATED,
    responses=_RESPONSES,
    summary="Analyse a domain name",
    description=(
        "Validates hostname syntax and evaluates structural heuristics (TLD abuse "
        "rate, subdomain depth, brand terms, label entropy for DGA-like names).\n\n"
        "If `ENABLE_DNS_LOOKUPS` is on, a passive A/AAAA resolution is performed "
        "through the configured resolver. No connection is made to the domain's "
        "services."
    ),
)
async def analyze_domain(
    request: Request, payload: DomainAnalysisRequest, db: Session = Depends(get_db)
) -> AnalysisDetail:
    record = await analysis_service.analyze_domain(
        db, payload.domain, owner_key=resolve_owner_key(request)
    )
    return AnalysisDetail.model_validate(record, from_attributes=True)


@router.post(
    "/ip",
    response_model=AnalysisDetail,
    status_code=status.HTTP_201_CREATED,
    responses=_RESPONSES,
    summary="Analyse an IP address",
    description=(
        "Classifies an IPv4/IPv6 address against the IANA special-purpose "
        "registries and, when enabled, performs a reverse (PTR) lookup.\n\n"
        "No packets are sent to the address: there is no ping, no port scan and no "
        "connection attempt."
    ),
)
async def analyze_ip(
    request: Request, payload: IPAnalysisRequest, db: Session = Depends(get_db)
) -> AnalysisDetail:
    record = await analysis_service.analyze_ip(
        db, payload.ip, owner_key=resolve_owner_key(request)
    )
    return AnalysisDetail.model_validate(record, from_attributes=True)


@router.post(
    "/hash",
    response_model=AnalysisDetail,
    status_code=status.HTTP_201_CREATED,
    responses=_RESPONSES,
    summary="Analyse a file hash",
    description=(
        "Identifies the digest algorithm from its length (MD5/SHA-1/SHA-256), "
        "reports collision-resistance caveats, and queries every enabled threat-"
        "intelligence provider.\n\n"
        "Try `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` -- "
        "the SHA-256 of the harmless EICAR anti-malware test file."
    ),
)
async def analyze_hash(
    request: Request, payload: HashAnalysisRequest, db: Session = Depends(get_db)
) -> AnalysisDetail:
    record = await analysis_service.analyze_hash(
        db, payload.hash, owner_key=resolve_owner_key(request)
    )
    return AnalysisDetail.model_validate(record, from_attributes=True)


@router.post(
    "/file",
    response_model=AnalysisDetail,
    status_code=status.HTTP_201_CREATED,
    responses={
        **_RESPONSES,
        413: {"description": "File exceeds the configured upload limit."},
    },
    summary="Analyse an uploaded file (static only)",
    description=(
        "Streams the upload into a quarantine directory outside the web root, then "
        "performs **static** analysis only:\n\n"
        "* MD5 / SHA-1 / SHA-256 digests\n"
        "* Content-based file type identification (magic bytes, not the declared "
        "  Content-Type or extension)\n"
        "* Shannon entropy, used to spot packed or encrypted content\n"
        "* Printable-string extraction and suspicious-pattern matching\n"
        "* Extension/content mismatch and masquerading checks\n\n"
        "**The file is never executed, extracted, or parsed by a format handler.** "
        "By default the bytes are deleted immediately after analysis; the hashes "
        "and metadata are retained."
    ),
)
async def analyze_file(
    request: Request,
    file: UploadFile = File(..., description=f"Max {settings.max_upload_bytes // (1024 * 1024)} MB."),
    db: Session = Depends(get_db),
) -> AnalysisDetail:
    if not file.filename:
        raise ValidationFailure("A file with a filename is required.")

    def chunks():
        # Reading in bounded chunks means a large upload never has to fit in
        # memory, and storage can abort the moment the limit is crossed.
        while chunk := file.file.read(64 * 1024):
            yield chunk

    # Spooled uploads hit the disk once they outgrow their memory buffer, so
    # both the read and the quarantine write are blocking I/O. Off the event
    # loop they go, alongside the analysis itself.
    stored_path, size = await asyncio.to_thread(storage.store_stream, chunks())
    record = await analysis_service.analyze_file(
        db, stored_path, file.filename, size, owner_key=resolve_owner_key(request)
    )
    return AnalysisDetail.model_validate(record, from_attributes=True)
