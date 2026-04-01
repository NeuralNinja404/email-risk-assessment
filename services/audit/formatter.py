"""Audit formatter — CEF and JSON output for SIEM."""

from __future__ import annotations

from shared.schemas import AuditEvent


def format_cef(event: AuditEvent) -> str:
    """Format as Common Event Format (CEF) string."""
    severity_map = {"LOW": 3, "MEDIUM": 6, "HIGH": 9}
    severity = severity_map.get(event.risk_level.value, 5)

    return (
        f"CEF:0|EmailRisk|HybridAnalyzer|1.0|{event.risk_level.value}|"
        f"Email Attachment Risk Assessment|{severity}|"
        f"task_id={event.task_id} "
        f"risk_score={event.risk_score:.4f} "
        f"decision={event.decision.value} "
        f"s_sig={event.component_scores.s_sig:.3f} "
        f"s_beh={event.component_scores.s_beh:.3f} "
        f"s_rep={event.component_scores.s_rep:.3f} "
        f"s_ctx={event.component_scores.s_ctx:.3f} "
        f"processing_time_ms={event.total_processing_time_ms}"
    )


def format_json(event: AuditEvent) -> dict:
    """Format as SIEM-compatible JSON dict."""
    return {
        "event_type": f"RISK_{event.risk_level.value}",
        "event_id": event.event_id,
        "task_id": event.task_id,
        "risk_score": round(event.risk_score, 6),
        "risk_level": event.risk_level.value,
        "decision": event.decision.value,
        "explanation": event.explanation,
        "components": {
            "s_sig": round(event.component_scores.s_sig, 4),
            "s_beh": round(event.component_scores.s_beh, 4),
            "s_rep": round(event.component_scores.s_rep, 4),
            "s_ctx": round(event.component_scores.s_ctx, 4),
        },
        "weights": event.weights_used,
        "processing_time_ms": event.total_processing_time_ms,
        "timestamp": event.created_at.isoformat(),
    }
