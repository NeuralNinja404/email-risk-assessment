"""Tests for the Scoring engine — risk score calculation."""

from __future__ import annotations

import pytest

from services.scoring.engine import compute_risk_score
from shared.schemas import ComponentScores


class TestComputeRiskScore:
    def test_all_zero_scores(self) -> None:
        scores = ComponentScores(s_sig=0.0, s_beh=0.0, s_rep=0.0, s_ctx=0.0, beh_available=True)
        r, weights = compute_risk_score(scores)
        assert r == 0.0
        assert abs(sum(weights.values()) - 1.0) < 0.001

    def test_all_max_scores(self) -> None:
        scores = ComponentScores(s_sig=1.0, s_beh=1.0, s_rep=1.0, s_ctx=1.0, beh_available=True)
        r, weights = compute_risk_score(scores)
        assert r == 1.0

    def test_behavioral_dominant(self) -> None:
        """Behavioral score should have highest weight (0.40)."""
        scores = ComponentScores(s_sig=0.0, s_beh=1.0, s_rep=0.0, s_ctx=0.0, beh_available=True)
        r, _ = compute_risk_score(scores)
        assert 0.35 <= r <= 0.45  # ~0.40

    def test_weight_redistribution_without_behavioral(self) -> None:
        """When behavioral is unavailable, weights redistribute proportionally."""
        scores = ComponentScores(s_sig=1.0, s_beh=0.0, s_rep=1.0, s_ctx=1.0, beh_available=False)
        r, weights = compute_risk_score(scores)
        # Should be 1.0 since all available components are maxed
        assert abs(r - 1.0) < 0.01
        assert weights["w_beh"] == 0.0
        assert abs(sum(weights.values()) - 1.0) < 0.001

    def test_partial_scores(self) -> None:
        scores = ComponentScores(s_sig=0.5, s_beh=0.0, s_rep=0.3, s_ctx=0.2, beh_available=False)
        r, weights = compute_risk_score(scores)
        # Manual: w_sig=0.20/0.60=0.333, w_rep=0.25/0.60=0.417, w_ctx=0.15/0.60=0.250
        # R = 0.333*0.5 + 0.417*0.3 + 0.250*0.2 = 0.167 + 0.125 + 0.050 = 0.342
        assert 0.30 <= r <= 0.40

    def test_score_clamped_to_unit(self) -> None:
        """Score cannot exceed 1.0 or go below 0.0."""
        scores = ComponentScores(s_sig=1.5, s_beh=1.5, s_rep=1.5, s_ctx=1.5, beh_available=True)
        r, _ = compute_risk_score(scores)
        assert r <= 1.0

    def test_medium_risk_scenario(self) -> None:
        """Typical medium risk: some signature + context flags."""
        scores = ComponentScores(s_sig=0.3, s_beh=0.0, s_rep=0.4, s_ctx=0.6, beh_available=False)
        r, _ = compute_risk_score(scores)
        assert 0.30 <= r <= 0.70  # Medium range
