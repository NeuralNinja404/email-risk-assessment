"""Tests for the Audit formatter — CEF and JSON output."""

from __future__ import annotations

from datetime import datetime

from services.audit.formatter import format_cef, format_json
from shared.schemas import AuditEvent, ComponentScores, Decision, RiskLevel


def _make_event(**kwargs) -> AuditEvent:
    defaults = dict(
        task_id="test-task-001",
        risk_score=0.72,
        risk_level=RiskLevel.HIGH,
        decision=Decision.QUARANTINE,
        explanation="High risk detected",
        component_scores=ComponentScores(s_sig=0.6, s_beh=0.0, s_rep=0.8, s_ctx=0.5),
        weights_used={"w_sig": 0.33, "w_beh": 0.0, "w_rep": 0.42, "w_ctx": 0.25},
        total_processing_time_ms=1234,
    )
    defaults.update(kwargs)
    return AuditEvent(**defaults)


class TestCEFFormatter:
    def test_cef_structure(self) -> None:
        cef = format_cef(_make_event())
        assert cef.startswith("CEF:0|EmailRisk|HybridAnalyzer|1.0|")
        assert "HIGH" in cef
        assert "task_id=test-task-001" in cef

    def test_cef_severity_high(self) -> None:
        cef = format_cef(_make_event(risk_level=RiskLevel.HIGH))
        assert "|9|" in cef

    def test_cef_severity_low(self) -> None:
        cef = format_cef(_make_event(risk_level=RiskLevel.LOW, decision=Decision.ALLOW))
        assert "|3|" in cef

    def test_cef_contains_scores(self) -> None:
        cef = format_cef(_make_event())
        assert "s_sig=0.600" in cef
        assert "s_rep=0.800" in cef


class TestJSONFormatter:
    def test_json_structure(self) -> None:
        data = format_json(_make_event())
        assert data["event_type"] == "RISK_HIGH"
        assert data["task_id"] == "test-task-001"
        assert data["risk_score"] == 0.72
        assert data["decision"] == "QUARANTINE"

    def test_json_components(self) -> None:
        data = format_json(_make_event())
        assert data["components"]["s_sig"] == 0.6
        assert data["components"]["s_rep"] == 0.8

    def test_json_has_timestamp(self) -> None:
        data = format_json(_make_event())
        assert "timestamp" in data
