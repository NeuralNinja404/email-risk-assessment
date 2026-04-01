"""Reputation analysis — external Threat Intelligence API clients."""

from __future__ import annotations

import asyncio
import time

import httpx
import structlog
from pybreaker import CircuitBreaker
from tenacity import retry, stop_after_attempt, wait_exponential

from shared.config import settings
from shared.schemas import ReputationFeatures

logger = structlog.get_logger()

# ── Circuit Breakers (3 failures → 5 min cooldown) ──
vt_breaker = CircuitBreaker(fail_max=3, reset_timeout=300, name="virustotal")
otx_breaker = CircuitBreaker(fail_max=3, reset_timeout=300, name="alienvault_otx")
misp_breaker = CircuitBreaker(fail_max=3, reset_timeout=300, name="misp")
abusech_breaker = CircuitBreaker(fail_max=3, reset_timeout=300, name="abusech")

# Redis client (lazy init)
_redis = None


async def _get_redis():  # type: ignore[no-untyped-def]
    global _redis
    if _redis is None:
        try:
            import redis.asyncio as aioredis

            _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        except Exception:
            logger.warning("Redis unavailable, caching disabled")
    return _redis


async def _cache_get(key: str) -> str | None:
    r = await _get_redis()
    if r is None:
        return None
    try:
        return await r.get(key)
    except Exception:
        return None


async def _cache_set(key: str, value: str, ttl: int = 86400) -> None:
    r = await _get_redis()
    if r is None:
        return
    try:
        await r.set(key, value, ex=ttl)
    except Exception:
        pass


# ── VirusTotal v3 ──


async def query_virustotal(sha256: str) -> tuple[float, bool]:
    """Query VT for file hash. Returns (detection_ratio, available)."""
    if not settings.virustotal_api_key:
        return 0.0, False

    cache_key = f"vt:file:{sha256}"
    cached = await _cache_get(cache_key)
    if cached is not None:
        return float(cached), True

    try:

        @vt_breaker
        async def _query() -> float:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": settings.virustotal_api_key},
                )
                if resp.status_code == 404:
                    return 0.0
                resp.raise_for_status()
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                return malicious / total

        ratio = await _query()
        await _cache_set(cache_key, str(ratio), ttl=86400)
        return ratio, True
    except Exception:
        logger.warning("VirusTotal query failed", sha256=sha256)
        return 0.0, False


# ── AlienVault OTX ──


async def query_otx(sha256: str) -> int:
    """Query OTX for pulse count. Returns pulse_count."""
    if not settings.alienvault_otx_api_key:
        return 0

    cache_key = f"otx:file:{sha256}"
    cached = await _cache_get(cache_key)
    if cached is not None:
        return int(cached)

    try:

        @otx_breaker
        async def _query() -> int:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
                    headers={"X-OTX-API-KEY": settings.alienvault_otx_api_key},
                )
                if resp.status_code == 404:
                    return 0
                resp.raise_for_status()
                data = resp.json()
                return data.get("pulse_info", {}).get("count", 0)

        count = await _query()
        await _cache_set(cache_key, str(count), ttl=86400)
        return count
    except Exception:
        logger.warning("OTX query failed", sha256=sha256)
        return 0


# ── Abuse.ch MalwareBazaar ──


async def query_malwarebazaar(sha256: str) -> float:
    """Query MalwareBazaar. Returns 1.0 if known malware, 0.0 otherwise."""
    cache_key = f"mb:file:{sha256}"
    cached = await _cache_get(cache_key)
    if cached is not None:
        return float(cached)

    try:

        @abusech_breaker
        async def _query() -> float:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_info", "hash": sha256},
                )
                resp.raise_for_status()
                data = resp.json()
                if data.get("query_status") == "hash_not_found":
                    return 0.0
                return 1.0

        score = await _query()
        await _cache_set(cache_key, str(score), ttl=86400)
        return score
    except Exception:
        logger.warning("MalwareBazaar query failed", sha256=sha256)
        return 0.0


# ── Domain Reputation (VirusTotal) ──


async def query_domain_reputation(domain: str) -> float:
    """Query VT for domain reputation. Returns score [0, 1]."""
    if not domain or not settings.virustotal_api_key:
        return 0.0

    cache_key = f"vt:domain:{domain}"
    cached = await _cache_get(cache_key)
    if cached is not None:
        return float(cached)

    try:

        @vt_breaker
        async def _query() -> float:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": settings.virustotal_api_key},
                )
                if resp.status_code == 404:
                    return 0.0
                resp.raise_for_status()
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                return (malicious + suspicious * 0.5) / total

        score = await _query()
        await _cache_set(cache_key, str(score), ttl=3600)  # 1h TTL for domains
        return score
    except Exception:
        logger.warning("Domain reputation query failed", domain=domain)
        return 0.0


# ── Main Reputation Analysis ──


async def analyze(sha256: str, sender_domain: str) -> ReputationFeatures:
    """Run all reputation queries in parallel with fallback chain."""
    # Parallel queries
    vt_task = asyncio.create_task(query_virustotal(sha256))
    otx_task = asyncio.create_task(query_otx(sha256))
    mb_task = asyncio.create_task(query_malwarebazaar(sha256))
    domain_task = asyncio.create_task(query_domain_reputation(sender_domain))

    vt_ratio, vt_available = await vt_task
    otx_count = await otx_task
    mb_score = await mb_task
    domain_score = await domain_task

    # f_rep1: File hash reputation (fallback chain: VT → MalwareBazaar)
    if vt_available and vt_ratio > 0:
        f_rep1 = min(vt_ratio, 1.0)
    elif mb_score > 0:
        f_rep1 = mb_score
    else:
        # Normalize OTX pulse count (> 5 pulses → high risk)
        f_rep1 = min(otx_count / 5.0, 1.0) if otx_count > 0 else 0.0

    # f_rep2: Sender domain reputation
    f_rep2 = min(domain_score, 1.0)

    # f_rep3: IoC campaign association (OTX pulses + MalwareBazaar)
    campaign_signals = (1.0 if otx_count > 0 else 0.0) + mb_score
    f_rep3 = min(campaign_signals / 2.0, 1.0)

    return ReputationFeatures(
        f_rep1=round(f_rep1, 4),
        f_rep2=round(f_rep2, 4),
        f_rep3=round(f_rep3, 4),
        vt_detection_ratio=round(vt_ratio, 4),
        vt_available=vt_available,
        otx_pulse_count=otx_count,
    )
