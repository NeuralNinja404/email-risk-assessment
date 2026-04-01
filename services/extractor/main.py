"""Feature Extractor Service — orchestrator that coordinates all analysis modules."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import structlog
from sqlalchemy import update

from shared.config import settings
from shared.db import async_session, engine
from shared.logging import setup_logging
from shared.models import AnalysisTask
from shared.mq import consume_loop, create_consumer, create_producer, publish
from shared.schemas import AttachmentTask, ExtractionResult, FeatureVector

from services.extractor import behavioral, context, normalizer, reputation, signature

logger = structlog.get_logger()


async def handle_message(data: dict) -> None:
    start = time.monotonic()
    task = AttachmentTask(**data)
    task_id = task.task_id

    structlog.contextvars.bind_contextvars(task_id=task_id)
    logger.info("Extraction started", file=task.file_name, sha256=task.file_sha256)

    # Update status to EXTRACTING
    import uuid as _uuid

    async with async_session() as session:
        await session.execute(
            update(AnalysisTask).where(AnalysisTask.id == _uuid.UUID(task_id)).values(status="EXTRACTING")
        )
        await session.commit()

    # Step 2: File classification + detect MIME
    detected_mime = signature.detect_mime(task.file_path)
    file_ext = Path(task.file_name).suffix.lower()

    # Step 3: Signature analysis (fast — milliseconds)
    sig_features = signature.analyze(task.file_path, task.file_name)

    # Step 4 & 6: Parallel — reputation + context analysis
    rep_task = asyncio.create_task(
        reputation.analyze(task.file_sha256, task.email_metadata.sender_domain)
    )
    ctx_features = context.analyze(
        task.email_metadata, task.file_name, detected_mime,
        inner_extensions=sig_features.inner_extensions,
    )
    rep_features = await rep_task

    # Step 5: Compute preliminary scores for sandbox trigger decision
    prelim_scores = normalizer.compute_scores(
        sig_features, behavioral.BehavioralFeatures(), rep_features, ctx_features
    )
    trigger = behavioral.should_trigger_sandbox(prelim_scores.s_sig, prelim_scores.s_rep, file_ext)

    # Step 5b: Behavioral analysis (conditional)
    beh_features = await behavioral.analyze(task.file_path, file_ext, trigger)

    # Step 7: Final score computation
    scores = normalizer.compute_scores(sig_features, beh_features, rep_features, ctx_features)

    elapsed_ms = int((time.monotonic() - start) * 1000)

    # Build result
    features = FeatureVector(
        sig=sig_features,
        beh=beh_features,
        rep=rep_features,
        ctx=ctx_features,
    )

    result = ExtractionResult(
        task_id=task_id,
        features=features,
        scores=scores,
        processing_time_ms=elapsed_ms,
    )

    # Publish to scoring
    await publish(producer, "tasks.score", result, key=task_id)
    logger.info(
        "Extraction complete",
        s_sig=scores.s_sig,
        s_beh=scores.s_beh,
        s_rep=scores.s_rep,
        s_ctx=scores.s_ctx,
        sandbox_triggered=trigger,
        elapsed_ms=elapsed_ms,
    )


producer = None


async def main() -> None:
    global producer
    setup_logging("extractor")
    logger.info("Feature Extractor starting")

    producer = await create_producer()
    consumer = await create_consumer("tasks.extract", group_id="extractor-group")

    try:
        await consume_loop(consumer, handle_message)
    finally:
        if producer:
            await producer.stop()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
