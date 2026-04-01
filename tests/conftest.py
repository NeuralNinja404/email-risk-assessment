"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

# Override settings for testing
os.environ.setdefault("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
os.environ.setdefault("POSTGRES_HOST", "localhost")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("API_KEY", "test-api-key")
os.environ.setdefault("ATTACHMENT_STORAGE_PATH", tempfile.mkdtemp())


@pytest.fixture
def sample_benign_pdf(tmp_path: Path) -> Path:
    """Create a minimal benign PDF file."""
    pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Root 1 0 R /Size 4 >>
startxref
206
%%EOF"""
    f = tmp_path / "test.pdf"
    f.write_bytes(pdf_content)
    return f


@pytest.fixture
def sample_suspicious_zip(tmp_path: Path) -> Path:
    """Create a ZIP containing a .exe file."""
    import zipfile

    zip_path = tmp_path / "suspicious.zip"
    exe_path = tmp_path / "payload.exe"
    exe_path.write_bytes(b"MZ" + b"\x00" * 100)

    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(exe_path, "payload.exe")

    return zip_path


@pytest.fixture
def sample_email_metadata() -> dict:
    return {
        "sender": "attacker@evil.com",
        "sender_domain": "evil.com",
        "recipients": ["victim@company.com"],
        "subject": "URGENT: Verify Your Account Immediately",
        "message_id": "<123@evil.com>",
        "spf_result": "fail",
        "dkim_result": "fail",
        "dmarc_result": "fail",
        "reply_to": "collector@other-domain.com",
        "received_chain": [],
    }


@pytest.fixture
def benign_email_metadata() -> dict:
    return {
        "sender": "colleague@company.com",
        "sender_domain": "company.com",
        "recipients": ["user@company.com"],
        "subject": "Monthly report attached",
        "message_id": "<456@company.com>",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "reply_to": "",
        "received_chain": [],
    }
