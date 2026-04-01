from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field


# ── Enums ──


class TaskStatus(str, enum.Enum):
    PENDING = "PENDING"
    EXTRACTING = "EXTRACTING"
    SCORING = "SCORING"
    POLICY = "POLICY"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Decision(str, enum.Enum):
    ALLOW = "ALLOW"
    HOLD_FOR_REVIEW = "HOLD_FOR_REVIEW"
    QUARANTINE = "QUARANTINE"


class Priority(str, enum.Enum):
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Email Metadata ──


class EmailMetadata(BaseModel):
    sender: str = ""
    sender_domain: str = ""
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    message_id: str = ""
    spf_result: str = ""  # pass / fail / softfail / none
    dkim_result: str = ""
    dmarc_result: str = ""
    reply_to: str = ""
    received_chain: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None


# ── Tasks & Results flowing through Kafka ──


class AttachmentTask(BaseModel):
    """Published by Ingest → consumed by Extractor."""

    task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str
    file_name: str
    file_size: int
    file_sha256: str
    file_md5: str
    email_metadata: EmailMetadata = Field(default_factory=EmailMetadata)
    priority: Priority = Priority.NORMAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SignatureFeatures(BaseModel):
    f_sig1: float = 0.0  # critical signature match count (norm)
    f_sig2: float = 0.0  # YARA / IoC binary match
    f_sig3: float = 0.0  # AV confidence level (norm)
    yara_matches: list[str] = Field(default_factory=list)
    hash_known_malicious: bool = False
    inner_extensions: list[str] = Field(default_factory=list)  # extensions found inside containers


class BehavioralFeatures(BaseModel):
    f_beh1: float = 0.0  # suspicious file operations
    f_beh2: float = 0.0  # process injection indicators
    f_beh3: float = 0.0  # network connections to risky hosts
    f_beh4: float = 0.0  # protection evasion attempts
    sandbox_executed: bool = False
    sandbox_report_id: str = ""


class ReputationFeatures(BaseModel):
    f_rep1: float = 0.0  # file hash reputation
    f_rep2: float = 0.0  # sender domain reputation
    f_rep3: float = 0.0  # IoC campaign association
    vt_detection_ratio: float = 0.0
    vt_available: bool = True
    otx_pulse_count: int = 0
    misp_event_count: int = 0


class ContextFeatures(BaseModel):
    f_ctx1: float = 0.0  # file type mismatch
    f_ctx2: float = 0.0  # linguistic urgency markers
    f_ctx3: float = 0.0  # email header anomalies
    f_ctx4: float = 0.0  # rare file format score
    detected_mime: str = ""
    extension_mime: str = ""
    urgency_keywords_found: list[str] = Field(default_factory=list)


class FeatureVector(BaseModel):
    sig: SignatureFeatures = Field(default_factory=SignatureFeatures)
    beh: BehavioralFeatures = Field(default_factory=BehavioralFeatures)
    rep: ReputationFeatures = Field(default_factory=ReputationFeatures)
    ctx: ContextFeatures = Field(default_factory=ContextFeatures)


class ComponentScores(BaseModel):
    s_sig: float = 0.0
    s_beh: float = 0.0
    s_rep: float = 0.0
    s_ctx: float = 0.0
    beh_available: bool = False


class ExtractionResult(BaseModel):
    """Published by Extractor → consumed by Scoring."""

    task_id: str
    features: FeatureVector
    scores: ComponentScores
    processing_time_ms: int = 0


class RiskResult(BaseModel):
    """Published by Scoring → consumed by Policy."""

    task_id: str
    risk_score: float
    component_scores: ComponentScores
    weights_used: dict[str, float] = Field(default_factory=dict)
    processing_time_ms: int = 0


class PolicyResult(BaseModel):
    """Published by Policy → consumed by Audit."""

    task_id: str
    risk_score: float
    risk_level: RiskLevel
    decision: Decision
    requires_review: bool = False
    gray_zone: bool = False
    explanation: str = ""
    component_scores: ComponentScores
    weights_used: dict[str, float] = Field(default_factory=dict)
    processing_time_ms: int = 0


class AuditEvent(BaseModel):
    """Final structured audit record."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str
    risk_score: float
    risk_level: RiskLevel
    decision: Decision
    explanation: str = ""
    component_scores: ComponentScores
    weights_used: dict[str, float] = Field(default_factory=dict)
    total_processing_time_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── API Response Models ──


class SubmitResponse(BaseModel):
    task_id: str
    status: TaskStatus = TaskStatus.PENDING
    message: str = "Attachment accepted for analysis"


class StatusResponse(BaseModel):
    task_id: str
    status: TaskStatus
    risk_score: float | None = None
    risk_level: RiskLevel | None = None
    decision: Decision | None = None
    explanation: str | None = None
    component_scores: ComponentScores | None = None
    processing_time_ms: int | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None
