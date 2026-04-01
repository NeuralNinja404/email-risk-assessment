"""Ingest Service — FastAPI HTTP API for submitting email attachments."""

from __future__ import annotations

import hashlib
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.db import async_session, engine
from shared.logging import setup_logging
from shared.models import AnalysisResult, AnalysisTask, Base
from shared.mq import create_producer, publish
from shared.schemas import AttachmentTask, EmailMetadata, StatusResponse, SubmitResponse, TaskStatus

logger = structlog.get_logger()

producer = None
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.ingest_rate_limit])


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    global producer
    setup_logging("ingest")
    # Create tables if they don't exist (dev convenience; production uses Alembic)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    producer = await create_producer()
    logger.info("Ingest service started")
    yield
    if producer:
        await producer.stop()
    await engine.dispose()


app = FastAPI(title="Email Risk Assessment — Ingest", version="0.1.0", lifespan=lifespan)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


# ── Auth dependency ──


def verify_api_key(request: Request) -> None:
    key = request.headers.get("X-API-Key", "")
    if not key or key != settings.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


# ── Routes ──


@app.get("/api/v1/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/submit", response_model=SubmitResponse, dependencies=[Depends(verify_api_key)])
@limiter.limit(settings.ingest_rate_limit)
async def submit_attachment(
    request: Request,
    file: UploadFile = File(...),
    email_metadata_json: str = Form(default="{}"),
) -> SubmitResponse:
    # Validate file size
    content = await file.read()
    max_bytes = settings.max_file_size_mb * 1024 * 1024
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {settings.max_file_size_mb}MB limit",
        )
    if len(content) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")

    # Compute hashes
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()  # noqa: S324 — used for identification, not security

    # Parse email metadata
    import json

    try:
        meta_dict = json.loads(email_metadata_json)
        email_meta = EmailMetadata(**meta_dict)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email_metadata_json")

    # Store file
    storage = Path(settings.attachment_storage_path)
    storage.mkdir(parents=True, exist_ok=True)
    file_path = storage / sha256
    file_path.write_bytes(content)

    # Create DB record
    async with async_session() as session:
        task = AnalysisTask(
            file_sha256=sha256,
            file_md5=md5,
            file_name=file.filename or "unknown",
            file_size=len(content),
            file_path=str(file_path),
            email_metadata=email_meta.model_dump(mode="json"),
            status="PENDING",
        )
        session.add(task)
        await session.commit()
        await session.refresh(task)
        task_id = str(task.id)

    # Publish to Kafka
    kafka_task = AttachmentTask(
        task_id=task_id,
        file_path=str(file_path),
        file_name=file.filename or "unknown",
        file_size=len(content),
        file_sha256=sha256,
        file_md5=md5,
        email_metadata=email_meta,
    )
    await publish(producer, "tasks.extract", kafka_task, key=sha256)

    logger.info("Attachment submitted", task_id=task_id, sha256=sha256, size=len(content))
    return SubmitResponse(task_id=task_id)


@app.get("/api/v1/status/{task_id}", response_model=StatusResponse, dependencies=[Depends(verify_api_key)])
async def get_status(task_id: str) -> StatusResponse:
    import uuid as _uuid

    try:
        tid = _uuid.UUID(task_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid task_id format")

    async with async_session() as session:
        task = await session.get(AnalysisTask, tid)
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

        result = None
        if task.status in ("COMPLETED", "POLICY"):
            row = await session.execute(
                select(AnalysisResult).where(AnalysisResult.task_id == tid).order_by(AnalysisResult.created_at.desc())
            )
            result = row.scalars().first()

        from shared.schemas import ComponentScores, Decision, RiskLevel

        return StatusResponse(
            task_id=task_id,
            status=TaskStatus(task.status),
            risk_score=result.risk_score if result else None,
            risk_level=RiskLevel(result.risk_level) if result and result.risk_level else None,
            decision=Decision(result.decision) if result and result.decision else None,
            explanation=result.explanation if result else None,
            component_scores=ComponentScores(
                s_sig=result.s_sig, s_beh=result.s_beh, s_rep=result.s_rep, s_ctx=result.s_ctx
            )
            if result
            else None,
            processing_time_ms=result.processing_time_ms if result else None,
            created_at=task.created_at,
            completed_at=result.created_at if result else None,
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("services.ingest.main:app", host="0.0.0.0", port=8000, reload=True)
