"""Persistence model for a completed analysis.

Design note: findings, technical details, provider results and ATT&CK
associations are stored as JSON rather than in child tables. They are
write-once, always read as a whole with their parent, and never queried
field-by-field -- normalising them would add joins without buying anything.
The columns that *are* filtered and sorted (type, verdict, score, date) are
first-class indexed columns.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from ..database.session import Base
from .enums import AnalysisStatus, IndicatorType, Verdict

# JSONB on PostgreSQL, plain JSON everywhere else. JSONB stores a parsed binary
# form rather than reformatted text, so it is both smaller and queryable with
# containment operators -- which is what a future "find every analysis whose
# findings include X" feature would need. SQLite has no equivalent, and the
# variant keeps that difference out of the model definition.
JSONColumn = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Human-quotable reference (SC-XXXXXX) used in reports and support tickets.
    reference: Mapped[str] = mapped_column(String(16), unique=True, index=True, nullable=False)

    indicator_type: Mapped[IndicatorType] = mapped_column(String(16), index=True, nullable=False)
    # The submitted value, normalised. For file submissions this is the
    # sanitised original filename; the raw bytes are never persisted.
    indicator: Mapped[str] = mapped_column(Text, nullable=False)
    indicator_display: Mapped[str] = mapped_column(String(255), nullable=False)

    risk_score: Mapped[int] = mapped_column(Integer, index=True, nullable=False, default=0)
    verdict: Mapped[Verdict] = mapped_column(String(16), index=True, nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(String(16), nullable=False, default=AnalysisStatus.COMPLETED)

    findings: Mapped[list] = mapped_column(JSONColumn, nullable=False, default=list)
    details: Mapped[dict] = mapped_column(JSONColumn, nullable=False, default=dict)
    provider_results: Mapped[list] = mapped_column(JSONColumn, nullable=False, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSONColumn, nullable=False, default=list)

    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True, nullable=False
    )

    # Seeded rows are synthetic. Flagging them keeps demo data from being
    # mistaken for real intelligence in screenshots or exports. They are also
    # the one category visible to every workspace.
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Anonymous workspace this analysis belongs to. NULL means unowned: seeded
    # demo rows, and anything created by a client that sent no key. Indexed
    # because every read filters on it. See core/owner.py for the threat model
    # -- this is isolation between browsers, not authentication.
    owner_key: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)

    __table_args__ = (
        Index("ix_analyses_created_type", "created_at", "indicator_type"),
        Index("ix_analyses_verdict_created", "verdict", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Analysis {self.reference} {self.indicator_type}={self.indicator_display} {self.verdict}>"
