"""Context analysis — email metadata, linguistic markers, file type mismatch."""

from __future__ import annotations

import re
from pathlib import Path

import structlog

from shared.schemas import ContextFeatures, EmailMetadata

logger = structlog.get_logger()

# ── Urgency Markers ──

URGENCY_PATTERNS_EN = [
    r"\bURGENT\b",
    r"\bIMMEDIATELY\b",
    r"\bACTION\s+REQUIRED\b",
    r"\bVERIFY\s+YOUR\s+ACCOUNT\b",
    r"\bSUSPEND\w*\b",
    r"\bCONFIRM\s+(YOUR\s+)?(IDENTITY|PAYMENT|ORDER)\b",
    r"\bCLICK\s+HERE\s+(NOW|IMMEDIATELY)\b",
    r"\bFINAL\s+(NOTICE|WARNING)\b",
    r"\bYOUR\s+ACCOUNT\s+(HAS\s+BEEN|WILL\s+BE)\b",
    r"\bEXPIR(E|ES|ED|ING)\b",
]

URGENCY_PATTERNS_UK = [
    r"\bТЕРМІНОВО\b",
    r"\bНЕГАЙНО\b",
    r"\bПІДТВЕРДІТЬ\b",
    r"\bУВАГА\b",
    r"\bОСТАННЄ\s+ПОПЕРЕДЖЕННЯ\b",
    r"\bВАШ\s+ОБЛІКОВИЙ\s+ЗАПИС\b",
    r"\bБЛОКУВАННЯ\b",
]

# ── File Format Risk Scores ──

FORMAT_RISK: dict[str, float] = {
    # High risk
    ".iso": 1.0, ".img": 1.0, ".vhd": 1.0, ".vhdx": 1.0,
    ".hta": 1.0, ".lnk": 1.0, ".scr": 1.0,
    ".wsf": 1.0, ".js": 1.0, ".vbs": 1.0, ".vbe": 1.0,
    ".jse": 1.0, ".wsh": 1.0, ".wsc": 1.0,
    # Medium risk
    ".exe": 0.7, ".dll": 0.7, ".bat": 0.7, ".cmd": 0.7,
    ".ps1": 0.7, ".msi": 0.7, ".com": 0.7, ".pif": 0.7,
    # Low risk (macro-enabled)
    ".docm": 0.5, ".xlsm": 0.5, ".pptm": 0.5,
    ".dotm": 0.5, ".xltm": 0.5,
    # Safe
    ".pdf": 0.05, ".docx": 0.0, ".xlsx": 0.0, ".pptx": 0.0,
    ".png": 0.0, ".jpg": 0.0, ".jpeg": 0.0, ".gif": 0.0,
    ".txt": 0.0, ".csv": 0.0, ".rtf": 0.05,
}

# ── MIME vs Extension Mismatch Mapping ──

EXPECTED_MIMES: dict[str, set[str]] = {
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"},
    ".pdf": {"application/pdf"},
    ".exe": {"application/x-dosexec", "application/x-executable", "application/x-msdos-program"},
    ".zip": {"application/zip", "application/x-zip-compressed"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".gif": {"image/gif"},
    ".txt": {"text/plain"},
}


def analyze_urgency(subject: str, body: str = "") -> tuple[float, list[str]]:
    """Detect urgency/phishing markers in subject + body. Returns (score, found_keywords)."""
    text = f"{subject} {body}".upper()
    found = []

    for pattern in URGENCY_PATTERNS_EN + URGENCY_PATTERNS_UK:
        if re.search(pattern, text, re.IGNORECASE):
            found.append(pattern)

    max_patterns = 5.0
    score = min(len(found) / max_patterns, 1.0)
    return round(score, 4), found


def analyze_headers(meta: EmailMetadata) -> float:
    """Score email header anomalies. Returns f_ctx3 ∈ [0, 1]."""
    score = 0.0

    # SPF/DKIM/DMARC failures
    if meta.spf_result.lower() in ("fail", "softfail"):
        score += 0.3
    if meta.dkim_result.lower() in ("fail", "none"):
        score += 0.3
    if meta.dmarc_result.lower() in ("fail", "none"):
        score += 0.4

    # Reply-To mismatch with sender
    if meta.reply_to and meta.sender:
        sender_domain = meta.sender.split("@")[-1].lower() if "@" in meta.sender else ""
        reply_domain = meta.reply_to.split("@")[-1].lower() if "@" in meta.reply_to else ""
        if sender_domain and reply_domain and sender_domain != reply_domain:
            score += 0.2

    return round(min(score, 1.0), 4)


def analyze_file_type_mismatch(file_name: str, detected_mime: str) -> float:
    """Check if detected MIME matches expected MIME for file extension."""
    ext = Path(file_name).suffix.lower()
    expected = EXPECTED_MIMES.get(ext)

    if expected is None:
        # Unknown extension — slightly suspicious
        return 0.1 if ext else 0.3

    if detected_mime in expected:
        return 0.0  # Match — no mismatch

    # Mismatch detected
    return 0.8


def analyze_format_risk(file_name: str) -> float:
    """Score file format rarity/risk."""
    ext = Path(file_name).suffix.lower()
    return FORMAT_RISK.get(ext, 0.3)  # Unknown = 0.3


# ── Main Context Analysis ──


def analyze(
    meta: EmailMetadata,
    file_name: str,
    detected_mime: str,
    inner_extensions: list[str] | None = None,
) -> ContextFeatures:
    """Run full context analysis."""
    # f_ctx1: file type mismatch
    f_ctx1 = analyze_file_type_mismatch(file_name, detected_mime)

    # f_ctx2: urgency markers
    f_ctx2, keywords = analyze_urgency(meta.subject)

    # f_ctx3: header anomalies
    f_ctx3 = analyze_headers(meta)

    # f_ctx4: file format risk — use riskiest inner file if container
    f_ctx4 = analyze_format_risk(file_name)
    if inner_extensions:
        inner_risk = max(analyze_format_risk(f"x{ext}") for ext in inner_extensions)
        f_ctx4 = max(f_ctx4, inner_risk)

    ext_mime = ""
    ext = Path(file_name).suffix.lower()
    expected = EXPECTED_MIMES.get(ext, set())
    if expected:
        ext_mime = next(iter(expected))

    return ContextFeatures(
        f_ctx1=f_ctx1,
        f_ctx2=f_ctx2,
        f_ctx3=f_ctx3,
        f_ctx4=f_ctx4,
        detected_mime=detected_mime,
        extension_mime=ext_mime,
        urgency_keywords_found=keywords,
    )
