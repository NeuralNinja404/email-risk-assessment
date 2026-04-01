"""Kafka producer / consumer helpers built on aiokafka."""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from pydantic import BaseModel

from shared.config import settings

logger = logging.getLogger(__name__)


async def create_producer() -> AIOKafkaProducer:
    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=lambda v: json.dumps(v, default=str).encode(),
        key_serializer=lambda k: k.encode() if k else None,
        acks="all",
        retry_backoff_ms=500,
        request_timeout_ms=30_000,
    )
    await producer.start()
    return producer


async def create_consumer(
    topic: str,
    group_id: str,
    *,
    auto_offset_reset: str = "earliest",
) -> AIOKafkaConsumer:
    consumer = AIOKafkaConsumer(
        topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=group_id,
        auto_offset_reset=auto_offset_reset,
        value_deserializer=lambda v: json.loads(v.decode()),
        enable_auto_commit=False,
        max_poll_interval_ms=600_000,  # 10 min — allow long sandbox runs
    )
    await consumer.start()
    return consumer


async def publish(producer: AIOKafkaProducer, topic: str, message: BaseModel, key: str | None = None) -> None:
    payload = message.model_dump(mode="json")
    await producer.send_and_wait(topic, value=payload, key=key)
    logger.debug("Published to %s key=%s", topic, key)


async def consume_loop(
    consumer: AIOKafkaConsumer,
    handler: Callable[[dict[str, Any]], Awaitable[None]],
) -> None:
    """Consume messages in a loop, committing after each successful handler call."""
    try:
        async for msg in consumer:
            try:
                await handler(msg.value)
                await consumer.commit()
            except Exception:
                logger.exception("Handler error for message offset=%s", msg.offset)
                # commit anyway to avoid infinite retry; errors logged + stored in DB
                await consumer.commit()
    finally:
        await consumer.stop()
