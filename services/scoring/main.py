"""Scoring Service — computes integral risk score R."""

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
from shared.schemas import ComponentScores, ExtractionResult, RiskResult

logger = structlog.get_logger()


def compute_risk_score(scores: ComponentScores) -> tuple[float, dict[str, float]]:
    """
    R = w₁·S_sig + w₂·S_beh + w₃·S_rep + w₄·S_ctx

    When behavioral component is unavailable, redistribute its weight
    proportionally among available components.
    """
    w_sig = settings.weight_signature
    w_beh = settings.weight_behavioral
    w_rep = settings.weight_reputation
    w_ctx = settings.weight_context

    if not scores.beh_available:
        # Redistribute w_beh proportionally
        available_sum = w_sig + w_rep + w_ctx
        if available_sum > 0:
            w_sig = w_sig / available_sum
            w_rep = w_rep / available_sum
            w_ctx = w_ctx / available_sum
        w_beh = 0.0

    weights = {"w_sig": w_sig, "w_beh": w_beh, "w_rep": w_rep, "w_ctx": w_ctx}
    r = w_sig * scores.s_sig + w_beh * scores.s_beh + w_rep * scores.s_rep + w_ctx * scores.s_ctx

    # Clamp to [0, 1]
    r = max(0.0, min(1.0, r))
    return round(r, 6), weights


async def handle_message(data: dict) -> None:
    start = time.monotonic()
    result = ExtractionResult(**data)
    task_id = result.task_id

    structlog.contextvars.bind_contextvars(task_id=task_id)
    logger.info("Scoring started")

    risk_score, weights = compute_risk_score(result.scores)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    total_ms = result.processing_time_ms + elapsed_ms

    # Store result
    import uuid as _uuid

    async with async_session() as session:
        ar = AnalysisResult(
            task_id=_uuid.UUID(task_id),
            s_sig=result.scores.s_sig,
            s_beh=result.scores.s_beh,
            s_rep=result.scores.s_rep,
            s_ctx=result.scores.s_ctx,
            risk_score=risk_score,
            feature_vector=result.features.model_dump(mode="json"),
            weights_used=weights,
            processing_time_ms=total_ms,
        )
        session.add(ar)
        await session.execute(
            update(AnalysisTask).where(AnalysisTask.id == _uuid.UUID(task_id)).values(status="SCORING")
        )
        await session.commit()

    # Publish to policy
    risk_result = RiskResult(
        task_id=task_id,
        risk_score=risk_score,
        component_scores=result.scores,
        weights_used=weights,
        processing_time_ms=total_ms,
    )
    await publish(producer, "tasks.policy", risk_result, key=task_id)
    logger.info("Scoring complete", risk_score=risk_score, elapsed_ms=elapsed_ms)


producer = None


async def main() -> None:
    global producer
    setup_logging("scoring")
    logger.info("Scoring service starting")

    producer = await create_producer()
    consumer = await create_consumer("tasks.score", group_id="scoring-group")

    try:
        await consume_loop(consumer, handle_message)
    finally:
        if producer:
            await producer.stop()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
