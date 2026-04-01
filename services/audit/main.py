"""Audit Service — structured logging and SIEM-compatible output."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime

import structlog
from sqlalchemy import update

from shared.config import settings
from shared.db import async_session, engine
from shared.logging import setup_logging
from shared.models import AnalysisTask, AuditLog
from shared.mq import consume_loop, create_consumer
from shared.schemas import AuditEvent, PolicyResult

logger = structlog.get_logger()


def format_cef(event: AuditEvent) -> str:
    """Format audit event as CEF (Common Event Format) string."""
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


async def handle_message(data: dict) -> None:
    policy = PolicyResult(**data)
    task_id = policy.task_id

    structlog.contextvars.bind_contextvars(task_id=task_id)
    logger.info("Audit recording started")

    event = AuditEvent(
        task_id=task_id,
        risk_score=policy.risk_score,
        risk_level=policy.risk_level,
        decision=policy.decision,
        explanation=policy.explanation,
        component_scores=policy.component_scores,
        weights_used=policy.weights_used,
        total_processing_time_ms=policy.processing_time_ms,
    )

    cef = format_cef(event)

    # Store audit log
    import uuid as _uuid

    async with async_session() as session:
        log = AuditLog(
            task_id=_uuid.UUID(task_id),
            event_type=f"RISK_{event.risk_level.value}",
            event_data=event.model_dump(mode="json"),
            cef_string=cef,
        )
        session.add(log)
        await session.execute(
            update(AnalysisTask).where(AnalysisTask.id == _uuid.UUID(task_id)).values(status="COMPLETED")
        )
        await session.commit()

    # Emit structured log for SIEM ingestion
    logger.info(
        "AUDIT_EVENT",
        cef=cef,
        risk_score=event.risk_score,
        risk_level=event.risk_level.value,
        decision=event.decision.value,
    )


async def main() -> None:
    setup_logging("audit")
    logger.info("Audit service starting")

    consumer = await create_consumer("tasks.audit", group_id="audit-group")

    try:
        await consume_loop(consumer, handle_message)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
