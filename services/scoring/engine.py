"""Scoring engine — pure functions for risk calculation."""

from __future__ import annotations

from shared.config import settings
from shared.schemas import ComponentScores


def compute_risk_score(scores: ComponentScores) -> tuple[float, dict[str, float]]:
    """
    Integral risk score:  R = w₁·S_sig + w₂·S_beh + w₃·S_rep + w₄·S_ctx

    When behavioral component is unavailable, redistribute w_beh proportionally.
    """
    w_sig = settings.weight_signature
    w_beh = settings.weight_behavioral
    w_rep = settings.weight_reputation
    w_ctx = settings.weight_context

    if not scores.beh_available:
        available_sum = w_sig + w_rep + w_ctx
        if available_sum > 0:
            w_sig /= available_sum
            w_rep /= available_sum
            w_ctx /= available_sum
        w_beh = 0.0

    weights = {"w_sig": round(w_sig, 4), "w_beh": round(w_beh, 4), "w_rep": round(w_rep, 4), "w_ctx": round(w_ctx, 4)}
    r = w_sig * scores.s_sig + w_beh * scores.s_beh + w_rep * scores.s_rep + w_ctx * scores.s_ctx
    r = max(0.0, min(1.0, round(r, 6)))

    return r, weights
