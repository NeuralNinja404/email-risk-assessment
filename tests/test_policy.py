"""Tests for the Policy engine — threshold classification."""

from __future__ import annotations

import pytest

from services.policy.rules import classify_risk
from shared.schemas import Decision, RiskLevel


class TestClassifyRisk:
    def test_low_risk(self) -> None:
        level, decision, gray, _ = classify_risk(0.10)
        assert level == RiskLevel.LOW
        assert decision == Decision.ALLOW
        assert not gray

    def test_medium_risk(self) -> None:
        level, decision, gray, _ = classify_risk(0.50)
        assert level == RiskLevel.MEDIUM
        assert decision == Decision.HOLD_FOR_REVIEW
        assert not gray

    def test_high_risk(self) -> None:
        level, decision, gray, _ = classify_risk(0.85)
        assert level == RiskLevel.HIGH
        assert decision == Decision.QUARANTINE
        assert not gray

    def test_boundary_low(self) -> None:
        """Exactly at low threshold → MEDIUM."""
        level, decision, _, _ = classify_risk(0.30)
        assert level == RiskLevel.MEDIUM
        assert decision == Decision.HOLD_FOR_REVIEW

    def test_boundary_high(self) -> None:
        """Exactly at high threshold → HIGH."""
        level, decision, _, _ = classify_risk(0.70)
        assert level == RiskLevel.HIGH
        assert decision == Decision.QUARANTINE

    def test_gray_zone_lower(self) -> None:
        """Score within ±0.03 of low boundary → gray zone."""
        level, _, gray, explanation = classify_risk(0.29)
        assert gray
        assert "GRAY ZONE" in explanation

    def test_gray_zone_upper(self) -> None:
        """Score within ±0.03 of high boundary → gray zone."""
        level, _, gray, explanation = classify_risk(0.71)
        assert gray
        assert "GRAY ZONE" in explanation

    def test_zero_score(self) -> None:
        level, decision, _, _ = classify_risk(0.0)
        assert level == RiskLevel.LOW
        assert decision == Decision.ALLOW

    def test_max_score(self) -> None:
        level, decision, _, _ = classify_risk(1.0)
        assert level == RiskLevel.HIGH
        assert decision == Decision.QUARANTINE

    def test_explanation_contains_score(self) -> None:
        _, _, _, explanation = classify_risk(0.42)
        assert "0.42" in explanation
