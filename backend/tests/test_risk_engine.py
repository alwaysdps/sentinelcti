"""Risk engine: scoring arithmetic, band boundaries and explainability."""

from __future__ import annotations

import pytest

from app.analyzers.base import ok, signal
from app.models.enums import Severity, Verdict
from app.services import risk_engine


def points(n: int, severity: Severity = Severity.MEDIUM, code: str | None = None):
    return signal(code or f"c{n}_{severity.value}", f"Signal {n}", "desc", n, severity, "test")


class TestBands:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (0, Verdict.CLEAN), (19, Verdict.CLEAN),
            (20, Verdict.LOW_RISK), (49, Verdict.LOW_RISK),
            (50, Verdict.SUSPICIOUS), (69, Verdict.SUSPICIOUS),
            (70, Verdict.HIGH_RISK), (89, Verdict.HIGH_RISK),
            (90, Verdict.CRITICAL), (100, Verdict.CRITICAL),
        ],
    )
    def test_band_boundaries_are_inclusive(self, score, expected):
        verdict, _ = risk_engine.verdict_for_score(score)
        assert verdict is expected

    def test_out_of_range_scores_are_clamped(self):
        assert risk_engine.verdict_for_score(-10)[0] is Verdict.CLEAN
        assert risk_engine.verdict_for_score(999)[0] is Verdict.CRITICAL

    def test_bands_are_contiguous_and_cover_0_to_100(self):
        bands = risk_engine.bands_reference()
        assert bands[0]["min"] == 0
        assert bands[-1]["max"] == 100
        for lower, upper in zip(bands, bands[1:]):
            assert upper["min"] == lower["max"] + 1


class TestScoring:
    def test_no_signals_scores_zero_and_reads_clean(self):
        result = risk_engine.assess([])
        assert result.score == 0
        assert result.verdict is Verdict.CLEAN

    def test_pass_only_signals_score_zero(self):
        result = risk_engine.assess([ok("a", "A", "d", "test"), ok("b", "B", "d", "test")])
        assert result.score == 0
        assert result.breakdown == []

    def test_points_accumulate(self):
        result = risk_engine.assess([points(10), points(15), points(20)])
        assert result.base_points == 45
        assert result.verdict is Verdict.LOW_RISK

    def test_suspicious_band_is_reachable(self):
        result = risk_engine.assess([points(25), points(20), points(10)])
        assert result.score == 55
        assert result.verdict is Verdict.SUSPICIOUS

    def test_high_risk_band_is_reachable(self):
        result = risk_engine.assess([points(25), points(25), points(20), points(12)])
        assert result.verdict in (Verdict.HIGH_RISK, Verdict.CRITICAL)
        assert result.score >= 70

    def test_score_is_capped_at_100(self):
        result = risk_engine.assess([points(40) for _ in range(6)])
        assert result.score == 100
        assert result.capped is True
        assert result.base_points == 240  # the raw sum is still reported honestly


class TestCorroboration:
    def test_single_high_severity_signal_earns_no_bonus(self):
        result = risk_engine.assess([points(30, Severity.HIGH)])
        assert result.corroboration_bonus == 0
        assert result.score == 30

    def test_multiple_high_severity_signals_earn_a_bonus(self):
        result = risk_engine.assess(
            [points(20, Severity.HIGH, "h1"), points(20, Severity.HIGH, "h2")]
        )
        assert result.corroboration_bonus == 5
        assert result.score == 45

    def test_bonus_is_capped(self):
        signals = [points(5, Severity.HIGH, f"h{i}") for i in range(10)]
        result = risk_engine.assess(signals)
        assert result.corroboration_bonus == risk_engine.MAX_CORROBORATION_BONUS

    def test_medium_signals_do_not_corroborate(self):
        result = risk_engine.assess([points(20, Severity.MEDIUM, "m1"), points(20, Severity.MEDIUM, "m2")])
        assert result.corroboration_bonus == 0


class TestScoreFloors:
    """A positive identification sets a minimum verdict; heuristics only add."""

    def floor_signal(self, floor: int, pts: int = 0):
        return signal("identified", "Provider: malicious", "d", pts, Severity.HIGH, "intelligence",
                      score_floor=floor)

    def test_floor_raises_an_otherwise_low_score(self):
        result = risk_engine.assess([self.floor_signal(70, pts=40)])
        assert result.score == 70
        assert result.verdict is Verdict.HIGH_RISK
        assert result.floor_applied == 70
        assert "70" in result.floor_reason

    def test_floor_never_lowers_a_higher_score(self):
        result = risk_engine.assess([self.floor_signal(70, pts=40), points(50)])
        assert result.score == 90
        assert result.floor_applied == 0
        assert result.floor_reason is None

    def test_only_the_highest_floor_applies_and_floors_do_not_stack(self):
        result = risk_engine.assess([self.floor_signal(50), self.floor_signal(70)])
        assert result.score == 70

    def test_signals_without_a_floor_are_unaffected(self):
        result = risk_engine.assess([points(30)])
        assert result.floor_applied == 0

    def test_base_points_still_reported_honestly_under_a_floor(self):
        result = risk_engine.assess([self.floor_signal(70, pts=40)])
        # The score was lifted, but the report must not pretend 70 points of
        # heuristic evidence were found.
        assert result.base_points == 40


class TestExplainability:
    def test_breakdown_only_contains_scoring_signals(self):
        result = risk_engine.assess([points(10), ok("clean", "Clean", "d", "test")])
        assert [e.code for e in result.breakdown] == ["c10_medium"]

    def test_breakdown_is_ordered_by_contribution(self):
        result = risk_engine.assess([points(5), points(30), points(15)])
        assert [e.points for e in result.breakdown] == [30, 15, 5]

    def test_breakdown_points_sum_to_base_points(self):
        result = risk_engine.assess([points(7), points(13), points(21)])
        assert sum(e.points for e in result.breakdown) == result.base_points

    def test_serialised_assessment_is_self_describing(self):
        payload = risk_engine.assess([points(25, Severity.HIGH)]).as_dict()
        assert set(payload) >= {
            "score", "verdict", "summary", "base_points",
            "corroboration_bonus", "capped_at_maximum", "breakdown",
        }
        assert payload["breakdown"][0]["title"]
