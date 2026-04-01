"""Feature normalizer — compute component scores from raw features."""

from __future__ import annotations

from shared.schemas import (
    BehavioralFeatures,
    ComponentScores,
    ContextFeatures,
    ReputationFeatures,
    SignatureFeatures,
)


def compute_s_sig(f: SignatureFeatures) -> float:
    """S_sig = weighted average of signature features."""
    # Weights: f_sig1=0.3 (match count), f_sig2=0.5 (binary match), f_sig3=0.2 (AV confidence)
    score = 0.3 * f.f_sig1 + 0.5 * f.f_sig2 + 0.2 * f.f_sig3
    # Bonus for known malicious hash
    if f.hash_known_malicious:
        score = min(score + 0.3, 1.0)
    return round(max(0.0, min(1.0, score)), 4)


def compute_s_beh(f: BehavioralFeatures) -> float:
    """S_beh = weighted average of behavioral features."""
    if not f.sandbox_executed:
        return 0.0
    # Equal weights for 4 behavioral features
    score = 0.25 * f.f_beh1 + 0.25 * f.f_beh2 + 0.25 * f.f_beh3 + 0.25 * f.f_beh4
    return round(max(0.0, min(1.0, score)), 4)


def compute_s_rep(f: ReputationFeatures) -> float:
    """S_rep = weighted average of reputation features."""
    # Weights: f_rep1=0.5 (file hash), f_rep2=0.25 (domain), f_rep3=0.25 (campaign)
    score = 0.5 * f.f_rep1 + 0.25 * f.f_rep2 + 0.25 * f.f_rep3
    return round(max(0.0, min(1.0, score)), 4)


def compute_s_ctx(f: ContextFeatures) -> float:
    """S_ctx = weighted average of context features."""
    # Weights: f_ctx1=0.3 (mismatch), f_ctx2=0.2 (urgency), f_ctx3=0.3 (headers), f_ctx4=0.2 (format)
    score = 0.3 * f.f_ctx1 + 0.2 * f.f_ctx2 + 0.3 * f.f_ctx3 + 0.2 * f.f_ctx4
    return round(max(0.0, min(1.0, score)), 4)


def compute_scores(
    sig: SignatureFeatures,
    beh: BehavioralFeatures,
    rep: ReputationFeatures,
    ctx: ContextFeatures,
) -> ComponentScores:
    """Compute all four component scores from feature vectors."""
    return ComponentScores(
        s_sig=compute_s_sig(sig),
        s_beh=compute_s_beh(beh),
        s_rep=compute_s_rep(rep),
        s_ctx=compute_s_ctx(ctx),
        beh_available=beh.sandbox_executed,
    )
