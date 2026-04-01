"""Signature analysis — YARA rules, hash matching, file classification."""

from __future__ import annotations

import hashlib
import io
import os
import zipfile
from pathlib import Path

import structlog

logger = structlog.get_logger()

# Lazy-load optional deps
_yara = None
_magic = None


def _get_yara():  # type: ignore[no-untyped-def]
    global _yara
    if _yara is None:
        try:
            import yara

            _yara = yara
        except ImportError:
            logger.warning("yara-python not installed, signature scanning disabled")
    return _yara


def _get_magic():  # type: ignore[no-untyped-def]
    global _magic
    if _magic is None:
        try:
            import magic as m

            _magic = m
        except ImportError:
            logger.warning("python-magic not installed, MIME detection disabled")
    return _magic


# ── File format risk classification ──

HIGH_RISK_EXTENSIONS = frozenset({
    ".iso", ".img", ".vhd", ".vhdx", ".hta", ".lnk", ".scr",
    ".wsf", ".js", ".vbs", ".vbe", ".jse", ".wsh", ".wsc",
})
MEDIUM_RISK_EXTENSIONS = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".msi", ".com", ".pif",
})
LOW_RISK_EXTENSIONS = frozenset({
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
})

CONTAINER_EXTENSIONS = frozenset({
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".img", ".vhd",
})

MAX_EXTRACT_DEPTH = 5
MAX_EXTRACT_SIZE = 100 * 1024 * 1024  # 100 MB


# ── YARA Scanning ──

_compiled_rules = None


def _load_yara_rules() -> object | None:
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    yara = _get_yara()
    if yara is None:
        return None

    rules_dir = Path(__file__).resolve().parent.parent.parent / "yara_rules"
    if not rules_dir.exists():
        logger.warning("YARA rules directory not found", path=str(rules_dir))
        return None

    rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
    if not rule_files:
        logger.warning("No YARA rule files found")
        return None

    filepaths = {f"rule_{i}": str(f) for i, f in enumerate(rule_files)}
    try:
        _compiled_rules = yara.compile(filepaths=filepaths)
        logger.info("YARA rules loaded", count=len(rule_files))
    except Exception:
        logger.exception("Failed to compile YARA rules")
        return None

    return _compiled_rules


def scan_yara(file_path: str) -> tuple[list[str], int]:
    """Scan file with YARA rules. Returns (match_names, critical_count)."""
    rules = _load_yara_rules()
    if rules is None:
        return [], 0

    try:
        matches = rules.match(file_path)
        names = [m.rule for m in matches]
        # Count as "critical" matches that have meta tag severity=critical
        critical = sum(1 for m in matches if m.meta.get("severity") == "critical")
        return names, max(critical, len(names))
    except Exception:
        logger.exception("YARA scan failed", file_path=file_path)
        return [], 0


# ── Hash Matching ──


def compute_hashes(content: bytes) -> dict[str, str]:
    """Compute multiple hashes for a file's content."""
    result = {
        "sha256": hashlib.sha256(content).hexdigest(),
        "md5": hashlib.md5(content).hexdigest(),  # noqa: S324
    }

    try:
        import tlsh

        h = tlsh.hash(content)
        result["tlsh"] = h if h else ""
    except (ImportError, ValueError):
        result["tlsh"] = ""

    return result


# ── File Classification ──


def detect_mime(file_path: str) -> str:
    """Detect MIME type using libmagic."""
    m = _get_magic()
    if m is None:
        return "application/octet-stream"
    try:
        return m.from_file(file_path, mime=True)
    except Exception:
        return "application/octet-stream"


def get_extension(file_name: str) -> str:
    return Path(file_name).suffix.lower()


# ── Container extraction with zip-bomb protection ──


def extract_container(file_path: str, depth: int = 0) -> list[dict[str, str]]:
    """
    Recursively extract container files (ZIP only for prototype).
    Returns list of {path, sha256, extension, mime} for inner files.
    Protection: max depth, max total extracted size, compression ratio check.
    """
    if depth >= MAX_EXTRACT_DEPTH:
        logger.warning("Max extraction depth reached", depth=depth)
        return []

    ext = get_extension(file_path)
    if ext not in (".zip",):
        return []

    extracted = []
    total_size = 0

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                # Zip-bomb protection: ratio check
                if info.compress_size > 0 and info.file_size / info.compress_size > 1000:
                    logger.warning("Zip bomb suspect: high ratio", name=info.filename, ratio=info.file_size / info.compress_size)
                    continue

                if total_size + info.file_size > MAX_EXTRACT_SIZE:
                    logger.warning("Max extraction size reached")
                    break

                total_size += info.file_size
                content = zf.read(info.filename)
                sha = hashlib.sha256(content).hexdigest()
                inner_ext = get_extension(info.filename)

                extracted.append({
                    "name": info.filename,
                    "sha256": sha,
                    "extension": inner_ext,
                    "size": len(content),
                })

    except (zipfile.BadZipFile, Exception):
        logger.warning("Failed to extract container", file_path=file_path)

    return extracted


# ── Main Signature Analysis ──


from shared.schemas import SignatureFeatures


def analyze(file_path: str, file_name: str) -> SignatureFeatures:
    """Run full signature analysis pipeline on an attachment."""
    yara_matches, critical_count = scan_yara(file_path)

    # f_sig1: critical match count normalized to [0, 1], cap at 10
    f_sig1 = min(critical_count / 10.0, 1.0)

    # f_sig2: binary — any YARA or IoC match
    f_sig2 = 1.0 if len(yara_matches) > 0 else 0.0

    # f_sig3: AV confidence placeholder (will be enriched by reputation service)
    f_sig3 = 0.0

    # Check if hash matches known malicious (placeholder — real impl queries local DB)
    hash_known = False

    # Check container contents
    inner_files = extract_container(file_path)
    risky_extensions = HIGH_RISK_EXTENSIONS | MEDIUM_RISK_EXTENSIONS | LOW_RISK_EXTENSIONS
    inner_exts: list[str] = []
    for inner in inner_files:
        inner_exts.append(inner["extension"])
        if inner["extension"] in risky_extensions:
            # Boost signature score for risky inner files
            f_sig1 = min(f_sig1 + 0.3, 1.0)
            f_sig2 = 1.0

    return SignatureFeatures(
        f_sig1=round(f_sig1, 4),
        f_sig2=f_sig2,
        f_sig3=f_sig3,
        yara_matches=yara_matches,
        hash_known_malicious=hash_known,
        inner_extensions=inner_exts,
    )
