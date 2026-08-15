"""Listing, filtering and dashboard aggregation.

All counts are computed from the database at request time. Nothing on the
dashboard is hard-coded or cached -- if the number moves, it moved because a
row changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import Select, case, func, select
from sqlalchemy.orm import Session

from ..models.analysis import Analysis
from ..models.enums import IndicatorType, Verdict

SORTABLE_COLUMNS = {
    "created_at": Analysis.created_at,
    "risk_score": Analysis.risk_score,
    "indicator": Analysis.indicator_display,
    "indicator_type": Analysis.indicator_type,
    "verdict": Analysis.verdict,
}


@dataclass
class Page:
    items: list[Analysis]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        return max(1, -(-self.total // self.page_size))  # ceil division


def visible_to(owner_key: str | None):
    """The single visibility rule: your own workspace, plus shared demo data.

    Every read goes through this. Keeping it in one expression -- rather than
    repeating `where(owner_key == ...)` at each call site -- is what stops a
    future query from silently exposing one workspace to another, which is the
    failure this whole feature exists to prevent.
    """
    if owner_key is None:
        # No workspace: shared demo data only. A client with storage disabled
        # still gets a working tool, it just does not accumulate history.
        return Analysis.is_demo.is_(True)
    return (Analysis.owner_key == owner_key) | Analysis.is_demo.is_(True)


def _apply_filters(
    stmt: Select,
    *,
    owner_key: str | None,
    search: str | None,
    indicator_type: IndicatorType | None,
    verdict: Verdict | None,
    min_score: int | None,
    max_score: int | None,
) -> Select:
    stmt = stmt.where(visible_to(owner_key))
    if search:
        # ORM `like` binds the pattern as a parameter; the wildcards are ours,
        # the value is never concatenated into SQL text.
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            Analysis.indicator_display.ilike(pattern) | Analysis.reference.ilike(pattern)
        )
    if indicator_type:
        stmt = stmt.where(Analysis.indicator_type == indicator_type)
    if verdict:
        stmt = stmt.where(Analysis.verdict == verdict)
    if min_score is not None:
        stmt = stmt.where(Analysis.risk_score >= min_score)
    if max_score is not None:
        stmt = stmt.where(Analysis.risk_score <= max_score)
    return stmt


def list_analyses(
    db: Session,
    *,
    owner_key: str | None = None,
    page: int = 1,
    page_size: int = 20,
    search: str | None = None,
    indicator_type: IndicatorType | None = None,
    verdict: Verdict | None = None,
    min_score: int | None = None,
    max_score: int | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
) -> Page:
    page = max(1, page)
    page_size = max(1, min(100, page_size))

    filters = {
        "owner_key": owner_key,
        "search": search,
        "indicator_type": indicator_type,
        "verdict": verdict,
        "min_score": min_score,
        "max_score": max_score,
    }

    total = db.execute(
        _apply_filters(select(func.count()).select_from(Analysis), **filters)
    ).scalar_one()

    column = SORTABLE_COLUMNS.get(sort_by, Analysis.created_at)
    ordering = column.desc() if sort_dir.lower() == "desc" else column.asc()

    stmt = (
        _apply_filters(select(Analysis), **filters)
        # Secondary key on id keeps pagination stable when many rows share a
        # timestamp (which the seed script produces by design).
        .order_by(ordering, Analysis.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    items = list(db.execute(stmt).scalars().all())
    return Page(items=items, total=total, page=page, page_size=page_size)


def dashboard_stats(db: Session, *, owner_key: str | None = None, activity_days: int = 30) -> dict:
    # Every aggregate is scoped to the caller's workspace. A dashboard that
    # counted other people's submissions would leak both their activity volume
    # and, through "recent", the indicators themselves.
    scope = visible_to(owner_key)

    total = db.execute(select(func.count()).select_from(Analysis).where(scope)).scalar_one()

    verdict_rows = db.execute(
        select(Analysis.verdict, func.count()).where(scope).group_by(Analysis.verdict)
    ).all()
    by_verdict = {v.value: 0 for v in Verdict}
    for verdict, count in verdict_rows:
        by_verdict[str(verdict)] = count

    type_rows = db.execute(
        select(Analysis.indicator_type, func.count()).where(scope).group_by(Analysis.indicator_type)
    ).all()
    by_type = {t.value: 0 for t in IndicatorType}
    for indicator_type, count in type_rows:
        by_type[str(indicator_type)] = count

    average_score = db.execute(select(func.avg(Analysis.risk_score)).where(scope)).scalar() or 0

    recent = list(
        db.execute(
            select(Analysis)
            .where(scope)
            .order_by(Analysis.created_at.desc(), Analysis.id.desc())
            .limit(8)
        )
        .scalars()
        .all()
    )

    return {
        "total_analyses": total,
        # Headline counters group the five bands into the three states an
        # operator actually triages on.
        "malicious_count": by_verdict[Verdict.HIGH_RISK.value] + by_verdict[Verdict.CRITICAL.value],
        "suspicious_count": by_verdict[Verdict.SUSPICIOUS.value],
        "clean_count": by_verdict[Verdict.CLEAN.value] + by_verdict[Verdict.LOW_RISK.value],
        "average_risk_score": round(float(average_score), 1),
        "by_verdict": by_verdict,
        "by_indicator_type": by_type,
        "activity": activity_series(db, owner_key=owner_key, days=activity_days),
        "recent": recent,
    }


def _day_bucket(db: Session):
    """Truncate a timestamp to a day, in whichever dialect is in use.

    This is the one query that genuinely cannot be written once. `date(x)` is
    the SQLite spelling; PostgreSQL's `date_trunc('day', x)` is correct for
    `timestamptz` and, unlike a `CAST(... AS DATE)`, does not silently mangle
    SQLite's text timestamps into integers.
    """
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        return func.date_trunc("day", Analysis.created_at)
    return func.date(Analysis.created_at)


def _day_key(value) -> str:
    """Normalise whatever the dialect returned into an ISO date string."""
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    # SQLite hands back "YYYY-MM-DD"; slicing tolerates a trailing time part.
    return str(value)[:10]


def activity_series(db: Session, *, owner_key: str | None = None, days: int = 30) -> list[dict]:
    """Per-day counts for the last N days, zero-filled.

    Zero-filling in Python rather than SQL keeps this portable: generating a
    date series is dialect-specific, a dict lookup is not.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days - 1)
    since_midnight = since.replace(hour=0, minute=0, second=0, microsecond=0)

    bucket = _day_bucket(db)
    rows = db.execute(
        select(
            bucket.label("day"),
            func.count().label("count"),
            func.sum(
                case((Analysis.verdict.in_([Verdict.HIGH_RISK, Verdict.CRITICAL]), 1), else_=0)
            ).label("malicious"),
        )
        .where(Analysis.created_at >= since_midnight, visible_to(owner_key))
        .group_by(bucket)
    ).all()

    counts = {_day_key(row.day): (row.count, int(row.malicious or 0)) for row in rows}

    series = []
    for offset in range(days):
        day = (since_midnight + timedelta(days=offset)).date()
        total, malicious = counts.get(day.isoformat(), (0, 0))
        series.append({"date": day.isoformat(), "count": total, "malicious": malicious})
    return series
