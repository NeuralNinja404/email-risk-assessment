"""Policy Engine — threshold classification and decision making."""

from __future__ import annotations

import asyncio
import time

import structlog
from sqlalchemy import update

from shared.config import settings
from shared.db import async_session, engine
from shared.logging import setup_logging
from shared.models import AnalysisResult, AnalysisTask
from shared.mq import consume_loop, create_consumer, create_producer, publish
from shared.schemas import ComponentScores, Decision, PolicyResult, RiskLevel, RiskResult

logger = structlog.get_logger()


def classify_risk(risk_score: float) -> tuple[RiskLevel, Decision, bool, str]:
    """
    Classify risk score into level + decision.

    Thresholds:
      LOW:    R < threshold_low  (0.30)
      MEDIUM: threshold_low ≤ R < threshold_high  (0.70)
      HIGH:   R ≥ threshold_high

    Gray zones (±margin around boundaries) flag requires_review=True.
    """
    t_low = settings.threshold_low
    t_high = settings.threshold_high
    margin = settings.gray_zone_margin

    gray_zone = False
    requires_review = False

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

    # Gray zone detection
    if abs(risk_score - t_low) <= margin:
        gray_zone = True
        requires_review = True
        explanation += f" [GRAY ZONE: score within ±{margin} of low boundary]"
    elif abs(risk_score - t_high) <= margin:
        gray_zone = True
        requires_review = True
        explanation += f" [GRAY ZONE: score within ±{margin} of high boundary]"

    return level, decision, gray_zone, explanation


async def handle_message(data: dict) -> None:
    start = time.monotonic()
    risk = RiskResult(**data)
    task_id = risk.task_id

    structlog.contextvars.bind_contextvars(task_id=task_id)
    logger.info("Policy evaluation started", risk_score=risk.risk_score)

    level, decision, gray_zone, explanation = classify_risk(risk.risk_score)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    total_ms = risk.processing_time_ms + elapsed_ms

    # Update result in DB
    import uuid as _uuid

    async with async_session() as session:
        await session.execute(
            update(AnalysisResult)
            .where(AnalysisResult.task_id == _uuid.UUID(task_id))
            .values(risk_level=level.value, decision=decision.value, explanation=explanation, processing_time_ms=total_ms)
        )
        await session.execute(
            update(AnalysisTask).where(AnalysisTask.id == _uuid.UUID(task_id)).values(status="POLICY")
        )
        await session.commit()

    # Publish to audit
    policy_result = PolicyResult(
        task_id=task_id,
        risk_score=risk.risk_score,
        risk_level=level,
        decision=decision,
        requires_review=gray_zone,
        gray_zone=gray_zone,
        explanation=explanation,
        component_scores=risk.component_scores,
        weights_used=risk.weights_used,
        processing_time_ms=total_ms,
    )
    await publish(producer, "tasks.audit", policy_result, key=task_id)
    logger.info("Policy decision", level=level.value, decision=decision.value, gray_zone=gray_zone)


producer = None


async def main() -> None:
    global producer
    setup_logging("policy")
    logger.info("Policy engine starting")

    producer = await create_producer()
    consumer = await create_consumer("tasks.policy", group_id="policy-group")

    try:
        await consume_loop(consumer, handle_message)
    finally:
        if producer:
            await producer.stop()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
