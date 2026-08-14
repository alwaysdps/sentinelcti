"""Indicator analyzers.

Each module owns exactly one indicator type and exposes `analyze(...)`
returning an `AnalyzerResult`. Analyzers are pure with respect to the database
and the API: they take a value, they return observations. That is what makes
them directly unit-testable without a running application.
"""

from .base import Analyzer, AnalyzerResult, Signal, ok, signal

__all__ = ["Analyzer", "AnalyzerResult", "Signal", "ok", "signal"]
