"""Shared analyzer contract.

Every analyzer converts one indicator into a list of *signals*. A signal is a
single, named, explainable observation carrying the points it contributes to
the risk score. Analyzers never compute a score themselves -- keeping scoring
in one place (services/risk_engine.py) is what makes the number auditable and
lets the report say exactly why each point was added.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..models.enums import AnalysisStatus, IndicatorType, Severity


@dataclass(frozen=True)
class Signal:
    code: str
    title: str
    description: str
    points: int
    severity: Severity
    category: str
    # Potential ATT&CK technique IDs. "Potential" is load-bearing: a string in
    # a file is evidence of a capability being referenced, never proof it ran.
    mitre: tuple[str, ...] = ()
    # Minimum score this signal alone justifies. Reserved for *positive
    # identification* (a provider naming the indicator), as opposed to the
    # heuristics that make up `points`. See services/risk_engine.py.
    score_floor: int = 0


@dataclass
class AnalyzerResult:
    indicator: str
    indicator_display: str
    indicator_type: IndicatorType
    signals: list[Signal] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    status: AnalysisStatus = AnalysisStatus.COMPLETED
    # Value handed to threat-intel providers for lookup (hash, domain, ip...).
    lookup_key: str | None = None


class Analyzer(Protocol):
    """Structural contract implemented by each analyzer module's entrypoint."""

    def analyze(self, value: str) -> AnalyzerResult: ...


def signal(
    code: str,
    title: str,
    description: str,
    points: int,
    severity: Severity,
    category: str,
    mitre: tuple[str, ...] = (),
    score_floor: int = 0,
) -> Signal:
    return Signal(
        code=code,
        title=title,
        description=description,
        points=points,
        severity=severity,
        category=category,
        mitre=mitre,
        score_floor=score_floor,
    )


def ok(code: str, title: str, description: str, category: str) -> Signal:
    """A benign observation. Zero points, but reported -- absence of a finding
    is itself information the analyst wants to see confirmed."""
    return Signal(
        code=code,
        title=title,
        description=description,
        points=0,
        severity=Severity.PASS,
        category=category,
    )
