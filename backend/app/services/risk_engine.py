"""Transparent risk scoring.

The output is a **Risk Score**, not a probability of maliciousness. Nothing
here is calibrated against a labelled corpus, and it must never be presented as
if it were. What it *is*: a reproducible weighted sum of named, human-readable
heuristics, where every point can be traced back to the finding that produced
it. That traceability is the entire design goal -- an analyst can disagree with
a score by disagreeing with a specific line item.

Scoring model
-------------
    raw   = sum(points of triggered signals) + corroboration bonus
    score = min(100, max(raw, highest score floor))

Three deliberate choices:

1. **Saturating, not averaging.** Ten weak signals should be able to reach a
   high score; averaging would let a pile of benign checks dilute one severe
   finding.
2. **Corroboration bonus.** Independent evidence agreeing is stronger than the
   same evidence counted twice, so agreement across distinct high-severity
   findings adds a small bonus rather than each finding being inflated.
3. **Score floors.** Heuristics and identifications are different kinds of
   evidence and must not be added together on one scale. "This URL is long" is
   a weak prior; "a provider has this exact hash on file as malicious" is a
   positive identification. A floor lets an identification set a minimum
   verdict directly -- otherwise a known-malicious hash with no other
   structural findings would land in the Low Risk band purely because there
   was nothing else to add points for, which is exactly backwards.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..analyzers.base import Signal
from ..models.enums import Severity, Verdict

# Inclusive lower bounds. Documented here and in the README so the report and
# the docs can never drift apart -- both read this table.
VERDICT_BANDS: list[tuple[int, int, Verdict, str]] = [
    (0, 19, Verdict.CLEAN, "No meaningful risk indicators were found."),
    (20, 49, Verdict.LOW_RISK, "Minor or ambiguous indicators; likely benign."),
    (50, 69, Verdict.SUSPICIOUS, "Multiple indicators warrant manual review."),
    (70, 89, Verdict.HIGH_RISK, "Strong indicators of malicious intent."),
    (90, 100, Verdict.CRITICAL, "Severe, corroborated indicators. Treat as hostile."),
]

MAX_SCORE = 100
# Each additional distinct HIGH-severity finding beyond the first corroborates
# the others. Capped so corroboration can never dominate the base signals.
CORROBORATION_POINTS_PER_EXTRA_HIGH = 5
MAX_CORROBORATION_BONUS = 15


@dataclass(frozen=True)
class ScoreBreakdownEntry:
    code: str
    title: str
    points: int
    severity: Severity
    category: str


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    verdict: Verdict
    summary: str
    base_points: int
    corroboration_bonus: int
    capped: bool
    breakdown: list[ScoreBreakdownEntry]
    floor_applied: int = 0
    floor_reason: str | None = None

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "base_points": self.base_points,
            "corroboration_bonus": self.corroboration_bonus,
            "floor_applied": self.floor_applied,
            "floor_reason": self.floor_reason,
            "capped_at_maximum": self.capped,
            "breakdown": [
                {
                    "code": e.code,
                    "title": e.title,
                    "points": e.points,
                    "severity": e.severity.value,
                    "category": e.category,
                }
                for e in self.breakdown
            ],
        }


def verdict_for_score(score: int) -> tuple[Verdict, str]:
    clamped = max(0, min(MAX_SCORE, score))
    for low, high, verdict, summary in VERDICT_BANDS:
        if low <= clamped <= high:
            return verdict, summary
    return Verdict.CRITICAL, VERDICT_BANDS[-1][3]


def assess(signals: list[Signal]) -> RiskAssessment:
    scoring = [s for s in signals if s.points > 0]
    base_points = sum(s.points for s in scoring)

    high_severity_count = sum(1 for s in scoring if s.severity is Severity.HIGH)
    bonus = 0
    if high_severity_count > 1:
        bonus = min(
            MAX_CORROBORATION_BONUS,
            (high_severity_count - 1) * CORROBORATION_POINTS_PER_EXTRA_HIGH,
        )

    raw = base_points + bonus

    # A floor only ever raises the score, and only the single highest one
    # applies -- floors are minimum verdicts, not additional evidence.
    floor_signal = max(signals, key=lambda s: s.score_floor, default=None)
    floor = floor_signal.score_floor if floor_signal else 0
    floor_reason = (
        f"Minimum score of {floor} applied: {floor_signal.title}"
        if floor > raw and floor_signal
        else None
    )

    score = min(MAX_SCORE, max(raw, floor))
    verdict, summary = verdict_for_score(score)

    breakdown = [
        ScoreBreakdownEntry(
            code=s.code, title=s.title, points=s.points, severity=s.severity, category=s.category
        )
        # Heaviest contributor first: that is the order an analyst reads in.
        for s in sorted(scoring, key=lambda s: (-s.points, s.code))
    ]

    return RiskAssessment(
        score=score,
        verdict=verdict,
        summary=summary,
        base_points=base_points,
        corroboration_bonus=bonus,
        capped=raw > MAX_SCORE,
        breakdown=breakdown,
        floor_applied=floor if floor > raw else 0,
        floor_reason=floor_reason,
    )


def bands_reference() -> list[dict]:
    """Machine-readable band table, surfaced by the API for the UI legend."""
    return [
        {"min": low, "max": high, "verdict": verdict.value, "summary": summary}
        for low, high, verdict, summary in VERDICT_BANDS
    ]
