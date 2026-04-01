"""Policy rules — pure functions for threshold classification."""

from __future__ import annotations

from shared.config import settings
from shared.schemas import Decision, RiskLevel


def classify_risk(risk_score: float) -> tuple[RiskLevel, Decision, bool, str]:
    """Classify risk score → (level, decision, gray_zone, explanation)."""
    t_low = settings.threshold_low
    t_high = settings.threshold_high
    margin = settings.gray_zone_margin

    gray_zone = False

    if risk_score < t_low:
        level = RiskLevel.LOW
        decision = Decision.ALLOW
        explanation = f"Risk score {risk_score:.4f} below low threshold ({t_low}). Delivery allowed."
    elif risk_score < t_high:
        level = RiskLevel.MEDIUM
        decision = Decision.HOLD_FOR_REVIEW
        explanation = f"Risk score {risk_score:.4f} in medium range [{t_low}, {t_high}). Held for analyst review."
    else:
        level = RiskLevel.HIGH
        decision = Decision.QUARANTINE
        explanation = f"Risk score {risk_score:.4f} at or above high threshold ({t_high}). Quarantined."

    if abs(risk_score - t_low) <= margin:
        gray_zone = True
        explanation += f" [GRAY ZONE: ±{margin} of low boundary]"
    elif abs(risk_score - t_high) <= margin:
        gray_zone = True
        explanation += f" [GRAY ZONE: ±{margin} of high boundary]"

    return level, decision, gray_zone, explanation
