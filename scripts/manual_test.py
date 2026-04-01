"""Manual integration test — calls real APIs with configured keys."""

import asyncio
import sys
import os
import tempfile

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from shared.config import settings
from services.extractor import signature, context, reputation
from services.extractor.normalizer import compute_scores
from services.extractor.behavioral import BehavioralFeatures, should_trigger_sandbox
from services.scoring.engine import compute_risk_score
from services.policy.rules import classify_risk
from services.audit.formatter import format_cef, format_json
from shared.schemas import AuditEvent, EmailMetadata, ComponentScores


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


async def test_benign_pdf():
    section("SCENARIO 1: Benign PDF + legitimate sender")

    # Create a minimal PDF
    pdf = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
xref
0 4
trailer<</Root 1 0 R/Size 4>>
startxref
0
%%EOF"""

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(pdf)
        file_path = f.name

    file_name = "monthly_report.pdf"
    import hashlib
    sha256 = hashlib.sha256(pdf).hexdigest()

    meta = EmailMetadata(
        sender="colleague@company.com",
        sender_domain="company.com",
        subject="Monthly report attached",
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
    )

    # Step 1: Signature
    print("\n[1] Signature analysis...")
    sig = signature.analyze(file_path, file_name)
    print(f"    f_sig1={sig.f_sig1}, f_sig2={sig.f_sig2}, f_sig3={sig.f_sig3}")
    print(f"    YARA matches: {sig.yara_matches}")
    print(f"    Inner extensions: {sig.inner_extensions}")

    # Step 2: Reputation (REAL API CALLS)
    print("\n[2] Reputation analysis (live API)...")
    print(f"    VT key: {'configured' if settings.virustotal_api_key else 'MISSING'}")
    print(f"    OTX key: {'configured' if settings.alienvault_otx_api_key else 'MISSING'}")
    rep = await reputation.analyze(sha256, meta.sender_domain)
    print(f"    f_rep1={rep.f_rep1} (file hash)")
    print(f"    f_rep2={rep.f_rep2} (domain rep)")
    print(f"    f_rep3={rep.f_rep3} (campaign)")
    print(f"    VT ratio={rep.vt_detection_ratio}, VT available={rep.vt_available}")
    print(f"    OTX pulses={rep.otx_pulse_count}")

    # Step 3: Context
    print("\n[3] Context analysis...")
    detected_mime = signature.detect_mime(file_path)
    ctx = context.analyze(meta, file_name, detected_mime, inner_extensions=sig.inner_extensions)
    print(f"    f_ctx1={ctx.f_ctx1} (type mismatch)")
    print(f"    f_ctx2={ctx.f_ctx2} (urgency)")
    print(f"    f_ctx3={ctx.f_ctx3} (header anomalies)")
    print(f"    f_ctx4={ctx.f_ctx4} (format risk)")
    print(f"    Detected MIME: {detected_mime}")

    # Step 4: Normalize
    beh = BehavioralFeatures()
    scores = compute_scores(sig, beh, rep, ctx)
    print(f"\n[4] Component scores:")
    print(f"    S_sig={scores.s_sig}, S_beh={scores.s_beh}, S_rep={scores.s_rep}, S_ctx={scores.s_ctx}")
    print(f"    Behavioral available: {scores.beh_available}")

    # Step 5: Risk score
    r, weights = compute_risk_score(scores)
    print(f"\n[5] Risk score: R = {r}")
    print(f"    Weights: {weights}")

    # Step 6: Policy
    level, decision, gray, explanation = classify_risk(r)
    print(f"\n[6] Policy decision:")
    print(f"    Level: {level.value}")
    print(f"    Decision: {decision.value}")
    print(f"    Gray zone: {gray}")
    print(f"    Explanation: {explanation}")

    os.unlink(file_path)
    return r, level.value, decision.value


async def test_suspicious_zip():
    section("SCENARIO 2: ZIP with .exe + phishing metadata")

    import zipfile

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create fake exe
        exe_path = os.path.join(tmpdir, "payload.exe")
        with open(exe_path, "wb") as f:
            f.write(b"MZ" + b"\x90" * 200)

        # Create ZIP
        zip_path = os.path.join(tmpdir, "invoice.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.write(exe_path, "payload.exe")

        file_name = "invoice.zip"
        with open(zip_path, "rb") as f:
            content = f.read()
        import hashlib
        sha256 = hashlib.sha256(content).hexdigest()

        meta = EmailMetadata(
            sender="accounts@evil-corp.xyz",
            sender_domain="evil-corp.xyz",
            subject="URGENT: Verify Your Account IMMEDIATELY - Final Notice",
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
            reply_to="collector@other-domain.com",
        )

        # Step 1: Signature
        print("\n[1] Signature analysis...")
        sig = signature.analyze(zip_path, file_name)
        print(f"    f_sig1={sig.f_sig1}, f_sig2={sig.f_sig2}, f_sig3={sig.f_sig3}")
        print(f"    YARA matches: {sig.yara_matches}")
        print(f"    Inner extensions: {sig.inner_extensions}")

        # Step 2: Reputation
        print("\n[2] Reputation analysis (live API)...")
        rep = await reputation.analyze(sha256, meta.sender_domain)
        print(f"    f_rep1={rep.f_rep1}, f_rep2={rep.f_rep2}, f_rep3={rep.f_rep3}")
        print(f"    VT ratio={rep.vt_detection_ratio}, VT available={rep.vt_available}")

        # Step 3: Context
        print("\n[3] Context analysis...")
        detected_mime = signature.detect_mime(zip_path)
        ctx = context.analyze(meta, file_name, detected_mime, inner_extensions=sig.inner_extensions)
        print(f"    f_ctx1={ctx.f_ctx1} (type mismatch)")
        print(f"    f_ctx2={ctx.f_ctx2} (urgency: {ctx.urgency_keywords_found})")
        print(f"    f_ctx3={ctx.f_ctx3} (header anomalies)")
        print(f"    f_ctx4={ctx.f_ctx4} (format risk)")

        # Step 4: Normalize
        beh = BehavioralFeatures()
        # Use preliminary scores for sandbox trigger (as in real pipeline)
        prelim_scores = compute_scores(sig, beh, rep, ctx)
        trigger = should_trigger_sandbox(prelim_scores.s_sig, prelim_scores.s_rep, ".zip")
        print(f"\n    Sandbox trigger: {trigger}")
        scores = prelim_scores  # beh=stub, so prelim = final
        print(f"\n[4] Component scores:")
        print(f"    S_sig={scores.s_sig}, S_beh={scores.s_beh}, S_rep={scores.s_rep}, S_ctx={scores.s_ctx}")

        # Step 5: Risk score
        r, weights = compute_risk_score(scores)
        print(f"\n[5] Risk score: R = {r}")
        print(f"    Weights: {weights}")

        # Step 6: Policy
        level, decision, gray, explanation = classify_risk(r)
        print(f"\n[6] Policy decision:")
        print(f"    Level: {level.value}")
        print(f"    Decision: {decision.value}")
        print(f"    Gray zone: {gray}")
        print(f"    Explanation: {explanation}")

        # Step 7: Audit
        event = AuditEvent(
            task_id="manual-test-002",
            risk_score=r,
            risk_level=level,
            decision=decision,
            explanation=explanation,
            component_scores=scores,
            weights_used=weights,
        )
        cef = format_cef(event)
        print(f"\n[7] CEF output:")
        print(f"    {cef}")

        return r, level.value, decision.value


async def main():
    print("=" * 60)
    print("  EMAIL RISK ASSESSMENT — Manual Integration Test")
    print("  Using LIVE API keys from .env")
    print("=" * 60)

    r1, lvl1, dec1 = await test_benign_pdf()
    r2, lvl2, dec2 = await test_suspicious_zip()

    section("SUMMARY")
    print(f"  Benign PDF:      R={r1:.4f}  →  {lvl1} / {dec1}")
    print(f"  Suspicious ZIP:  R={r2:.4f}  →  {lvl2} / {dec2}")
    print()

    if dec1 == "ALLOW" and r1 < 0.30:
        print("  ✅ Benign PDF correctly classified as LOW risk")
    else:
        print(f"  ⚠️  Benign PDF: expected LOW/ALLOW, got {lvl1}/{dec1}")

    if r2 > r1:
        print("  ✅ Suspicious ZIP scored higher than benign PDF")
    else:
        print("  ⚠️  Suspicious ZIP should score higher than benign PDF")

    print()


if __name__ == "__main__":
    asyncio.run(main())
