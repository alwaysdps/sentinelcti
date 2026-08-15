"""Retrieval endpoints: history listing, single report, deletion."""

from __future__ import annotations

from enum import StrEnum

from fastapi import APIRouter, Depends, Path, Query, Request
from sqlalchemy.orm import Session

from ..core.owner import resolve_owner_key
from ..database import get_db
from ..models.enums import IndicatorType, Verdict
from ..schemas.analysis import AnalysisDetail, DeleteResponse, PaginatedAnalyses, PurgeResponse
from ..services import analysis_service, query_service

router = APIRouter(prefix="/api/analyses", tags=["History"])


@router.post(
    "/purge",
    response_model=PurgeResponse,
    summary="Delete every analysis in the caller's workspace",
    description=(
        "Empties the workspace identified by the `X-Owner-Key` header. Rows belonging "
        "to any other workspace are untouched, and a request without a valid key "
        "deletes nothing.\n\n"
        "The browser calls this as the tab closes, which is what makes a session's "
        "history disposable rather than merely hidden. It is also safe to call "
        "directly to clear your history on demand.\n\n"
        "Deliberately POST rather than DELETE: deployments commonly gate DELETE behind "
        "a shared token to stop a passer-by emptying the database, and this operation "
        "needs no such protection — the key you present is the only thing it can act on."
    ),
)
def purge_workspace(
    request: Request,
    db: Session = Depends(get_db),
) -> PurgeResponse:
    removed = analysis_service.purge_workspace(db, resolve_owner_key(request))
    return PurgeResponse(deleted=removed)


class SortField(StrEnum):
    """Sortable columns, mirroring `query_service.SORTABLE_COLUMNS`.

    The service layer keeps its own allowlist as the security boundary -- this
    enum is the *contract*, so the values show up in the OpenAPI schema and an
    unknown field is rejected instead of silently ignored.
    """

    CREATED_AT = "created_at"
    RISK_SCORE = "risk_score"
    INDICATOR = "indicator"
    INDICATOR_TYPE = "indicator_type"
    VERDICT = "verdict"


@router.get(
    "",
    response_model=PaginatedAnalyses,
    summary="List analyses",
    description=(
        "Paginated analysis history with search, filtering and sorting.\n\n"
        "`search` matches the indicator or the SC- reference. Sortable fields: "
        "`created_at`, `risk_score`, `indicator`, `indicator_type`, `verdict`."
    ),
)
def list_analyses(
    request: Request,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None, max_length=255, description="Indicator or reference substring."),
    indicator_type: IndicatorType | None = Query(None),
    verdict: Verdict | None = Query(None),
    min_score: int | None = Query(None, ge=0, le=100),
    max_score: int | None = Query(None, ge=0, le=100),
    # Declared as an enum rather than a free string so the allowed values appear
    # in the OpenAPI schema and an unknown field is reported to the caller.
    # Silently falling back to the default sort hid client typos: the response
    # looked fine but was ordered by something else entirely.
    sort_by: SortField = Query(SortField.CREATED_AT),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
) -> PaginatedAnalyses:
    page_result = query_service.list_analyses(
        db,
        owner_key=resolve_owner_key(request),
        page=page,
        page_size=page_size,
        search=search,
        indicator_type=indicator_type,
        verdict=verdict,
        min_score=min_score,
        max_score=max_score,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return PaginatedAnalyses(
        items=[AnalysisDetail.model_validate(i, from_attributes=True) for i in page_result.items],
        total=page_result.total,
        page=page_result.page,
        page_size=page_result.page_size,
        total_pages=page_result.total_pages,
    )


@router.get(
    "/{identifier}",
    response_model=AnalysisDetail,
    responses={404: {"description": "No analysis with that id or reference."}},
    summary="Get a full analysis report",
    description="Accepts either the numeric id or the SC-XXXXXX reference.",
)
def get_analysis(
    request: Request,
    identifier: str = Path(..., max_length=32, examples=["SC-K7M2QP"]),
    db: Session = Depends(get_db),
) -> AnalysisDetail:
    record = analysis_service.get_by_reference_or_id(db, identifier, owner_key=resolve_owner_key(request))
    return AnalysisDetail.model_validate(record, from_attributes=True)


@router.delete(
    "/{identifier}",
    response_model=DeleteResponse,
    responses={404: {"description": "No analysis with that id or reference."}},
    summary="Delete an analysis",
    description=(
        "Removes the stored report. Uploaded file bytes were already discarded at "
        "analysis time, so nothing further needs cleaning up."
    ),
)
def delete_analysis(
    request: Request,
    identifier: str = Path(..., max_length=32),
    db: Session = Depends(get_db),
) -> DeleteResponse:
    record = analysis_service.get_by_reference_or_id(db, identifier, owner_key=resolve_owner_key(request))
    reference = record.reference
    analysis_service.delete_analysis(db, identifier, owner_key=resolve_owner_key(request))
    return DeleteResponse(deleted=True, reference=reference)
