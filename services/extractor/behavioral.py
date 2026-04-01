"""Behavioral analysis — sandbox orchestration (CAPE/Cuckoo).

Phase 2: stub implementation.
Phase 3: full CAPE REST API integration.
"""

from __future__ import annotations

import structlog

from shared.config import settings
from shared.schemas import BehavioralFeatures

logger = structlog.get_logger()

# File types that trigger sandbox analysis
HIGH_RISK_TYPES = frozenset({
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1",
    ".hta", ".wsf", ".js", ".vbs", ".vbe", ".jse", ".wsh",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
    ".iso", ".img", ".vhd", ".lnk",
})


def should_trigger_sandbox(s_sig: float, s_rep: float, file_extension: str) -> bool:
    """
    Adaptive sandbox trigger logic (Algorithm Step 5):
    - S_sig >= 0.15 OR S_rep >= 0.15 OR file type is high-risk
    """
    if s_sig >= 0.15:
        return True
    if s_rep >= 0.15:
        return True
    if file_extension.lower() in HIGH_RISK_TYPES:
        return True
    return False


async def analyze(file_path: str, file_extension: str, trigger: bool) -> BehavioralFeatures:
    """
    Run behavioral/sandbox analysis.

    Currently a stub — returns empty features with sandbox_executed=False.
    Full implementation will:
    1. POST file to CAPE REST API
    2. Poll for completion
    3. Extract behavioral indicators from report
    """
    if not trigger:
        logger.debug("Sandbox skipped (trigger=False)")
        return BehavioralFeatures(sandbox_executed=False)

    if not settings.cape_api_url:
        logger.info("Sandbox skipped (CAPE not configured)")
        return BehavioralFeatures(sandbox_executed=False)

    # ── Phase 3: CAPE integration placeholder ──
    # TODO: Implement full CAPE REST API flow:
    #   POST /tasks/create/file → task_id
    #   GET /tasks/view/{id} → poll until "reported"
    #   GET /tasks/report/{id} → extract behavioral indicators
    #
    # Feature extraction from sandbox report:
    #   f_beh1: count of suspicious file ops (create/encrypt) / threshold
    #   f_beh2: process injection (WriteProcessMemory, CreateRemoteThread)
    #   f_beh3: network connections to unknown hosts / C2 domains
    #   f_beh4: evasion techniques (disable AV, ETW patching, VM checks)

    logger.info("Sandbox analysis not yet implemented, returning stub")
    return BehavioralFeatures(sandbox_executed=False)
