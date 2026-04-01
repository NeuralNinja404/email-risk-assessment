"""Tests for the Feature Extractor — context analysis and normalizer."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.extractor.context import (
    analyze_file_type_mismatch,
    analyze_format_risk,
    analyze_headers,
    analyze_urgency,
)
from services.extractor.normalizer import compute_s_ctx, compute_s_rep, compute_s_sig, compute_scores
from shared.schemas import (
    BehavioralFeatures,
    ComponentScores,
    ContextFeatures,
    EmailMetadata,
    ReputationFeatures,
    SignatureFeatures,
)


class TestUrgencyAnalysis:
    def test_no_urgency(self) -> None:
        score, keywords = analyze_urgency("Monthly report")
        assert score == 0.0
        assert len(keywords) == 0

    def test_urgent_subject(self) -> None:
        score, keywords = analyze_urgency("URGENT: Verify Your Account Immediately")
        assert score > 0.0
        assert len(keywords) >= 1

    def test_multiple_urgency_markers(self) -> None:
        score, keywords = analyze_urgency(
            "URGENT ACTION REQUIRED: Verify Your Account IMMEDIATELY or it expires"
        )
        assert score >= 0.4

    def test_ukrainian_urgency(self) -> None:
        score, keywords = analyze_urgency("ТЕРМІНОВО: Підтвердіть свій обліковий запис")
        assert score > 0.0


class TestHeaderAnalysis:
    def test_all_pass(self) -> None:
        meta = EmailMetadata(spf_result="pass", dkim_result="pass", dmarc_result="pass")
        assert analyze_headers(meta) == 0.0

    def test_all_fail(self) -> None:
        meta = EmailMetadata(spf_result="fail", dkim_result="fail", dmarc_result="fail")
        assert analyze_headers(meta) == 1.0

    def test_reply_to_mismatch(self) -> None:
        meta = EmailMetadata(
            sender="user@company.com",
            reply_to="attacker@evil.com",
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
        )
        score = analyze_headers(meta)
        assert score > 0.0


class TestFileTypeMismatch:
    def test_matching_pdf(self) -> None:
        assert analyze_file_type_mismatch("report.pdf", "application/pdf") == 0.0

    def test_mismatched_pdf(self) -> None:
        score = analyze_file_type_mismatch("report.pdf", "application/x-dosexec")
        assert score > 0.5

    def test_unknown_extension(self) -> None:
        score = analyze_file_type_mismatch("file.xyz", "application/octet-stream")
        assert 0.0 < score < 0.5


class TestFormatRisk:
    def test_safe_docx(self) -> None:
        assert analyze_format_risk("report.docx") == 0.0

    def test_high_risk_iso(self) -> None:
        assert analyze_format_risk("disk.iso") == 1.0

    def test_medium_risk_exe(self) -> None:
        assert analyze_format_risk("app.exe") == 0.7

    def test_unknown_format(self) -> None:
        assert analyze_format_risk("file.abc") == 0.3


class TestNormalizer:
    def test_clean_file_zero_scores(self) -> None:
        sig = SignatureFeatures()
        beh = BehavioralFeatures()
        rep = ReputationFeatures()
        ctx = ContextFeatures()
        scores = compute_scores(sig, beh, rep, ctx)
        assert scores.s_sig == 0.0
        assert scores.s_beh == 0.0
        assert scores.s_rep == 0.0
        assert scores.s_ctx == 0.0
        assert not scores.beh_available

    def test_high_signature_score(self) -> None:
        sig = SignatureFeatures(f_sig1=1.0, f_sig2=1.0, f_sig3=0.8)
        s = compute_s_sig(sig)
        assert s > 0.7

    def test_known_malicious_hash_bonus(self) -> None:
        sig_normal = SignatureFeatures(f_sig1=0.2, f_sig2=0.0, f_sig3=0.0)
        sig_known = SignatureFeatures(f_sig1=0.2, f_sig2=0.0, f_sig3=0.0, hash_known_malicious=True)
        assert compute_s_sig(sig_known) > compute_s_sig(sig_normal)

    def test_scores_bounded(self) -> None:
        sig = SignatureFeatures(f_sig1=2.0, f_sig2=2.0, f_sig3=2.0, hash_known_malicious=True)
        assert compute_s_sig(sig) <= 1.0
