# Email Risk Assessment

Hybrid method for integral risk assessment of email attachments in a corporate environment.

A microservice-based system for automated email attachment analysis that computes an integral risk score from four components: signature-based, behavioral, reputation, and contextual.

## Architecture

```
                    tasks.extract        tasks.score        tasks.policy       tasks.audit
┌──────────┐       ┌─────────────┐      ┌──────────┐      ┌────────────┐      ┌─────────┐
│  Ingest  │──────▶│  Extractor  │─────▶│ Scoring  │─────▶│   Policy   │─────▶│  Audit  │
│  (HTTP)  │ Kafka │ (Features)  │ Kafka│   (R)    │ Kafka│ (Decision) │ Kafka│  (SIEM) │
└────┬─────┘       └──────┬──────┘      └────┬─────┘      └─────┬──────┘      └────┬────┘
     │                    │                   │                  │                   │
     └────────────────────┴───────────────────┴──────────────────┴───────────────────┘
                                    PostgreSQL + Redis
```

### Services

| Service | Description | Port |
|---------|-------------|------|
| **Ingest** | FastAPI HTTP API — receives attachments and email metadata | 8000 |
| **Extractor** | Feature analysis: YARA, reputation APIs, email context | — |
| **Scoring** | Computes R = w₁·S_sig + w₂·S_beh + w₃·S_rep + w₄·S_ctx | — |
| **Policy** | Classification: LOW / MEDIUM / HIGH → ALLOW / HOLD / QUARANTINE | — |
| **Audit** | CEF + JSON logging for SIEM integration | — |

## Risk Scoring Formula

```
R = w₁·S_sig + w₂·S_beh + w₃·S_rep + w₄·S_ctx
```

| Component | Weight | Description |
|-----------|--------|-------------|
| S_sig | 0.20 | Signature analysis (YARA rules, hash matching) |
| S_beh | 0.40 | Behavioral analysis (sandbox execution) |
| S_rep | 0.25 | Reputation analysis (VirusTotal, OTX, MalwareBazaar) |
| S_ctx | 0.15 | Contextual analysis (SPF/DKIM/DMARC, urgency markers) |

When a component is unavailable (e.g. sandbox not configured), its weight is redistributed proportionally among the remaining components.

Risk classification:
- **LOW** (R < 0.30) — allow delivery
- **MEDIUM** (0.30 ≤ R < 0.70) — hold for analyst review
- **HIGH** (R ≥ 0.70) — quarantine + SOC incident

Gray zones (±0.03 around thresholds) flag the result for additional review.

## Tech Stack

- **Python 3.12+**
- **FastAPI** — HTTP API (Ingest service)
- **Apache Kafka** — message broker between services
- **PostgreSQL 16** — tasks, results, and audit log persistence
- **Redis 7** — reputation API response caching
- **YARA** — signature-based file scanning
- **Docker Compose** — orchestration

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Python 3.12+ (for local development)

### Run with Docker

```bash
cp .env.example .env
# Fill in API keys in .env (VirusTotal, OTX, etc.)

docker compose up -d --build
```

The API will be available at `http://localhost:8000`.

### Local Development

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Start infrastructure only
docker compose up -d kafka postgres redis kafka-init

# Run tests
make test
```

## API

### Submit an Attachment for Analysis

```bash
curl -X POST http://localhost:8000/api/v1/submit \
  -H "X-API-Key: YOUR_KEY" \
  -F "file=@attachment.pdf" \
  -F 'email_metadata_json={"sender":"user@example.com","sender_domain":"example.com","subject":"Report","spf_result":"pass","dkim_result":"pass","dmarc_result":"pass"}'
```

Response:
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "PENDING",
  "message": "Attachment accepted for analysis"
}
```

### Check Status

```bash
curl http://localhost:8000/api/v1/status/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: YOUR_KEY"
```

Response:
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "COMPLETED",
  "risk_score": 0.72,
  "risk_level": "HIGH",
  "decision": "QUARANTINE",
  "component_scores": {"s_sig": 0.6, "s_beh": 0.0, "s_rep": 0.8, "s_ctx": 0.5}
}
```

## Project Structure

```
email-risk-assessment/
├── docker-compose.yml          # Kafka, PostgreSQL, Redis + 5 services
├── pyproject.toml              # Dependencies and tooling config
├── Makefile                    # make up / test / lint / migrate
├── .env.example                # Configuration template
├── shared/                     # Shared library
│   ├── schemas.py              # Pydantic models
│   ├── config.py               # Settings (pydantic-settings)
│   ├── mq.py                   # Kafka producer/consumer helpers
│   ├── db.py                   # SQLAlchemy async engine
│   ├── models.py               # ORM models (AnalysisTask, AnalysisResult, AuditLog)
│   └── logging.py              # Structured logging (structlog)
├── services/
│   ├── ingest/main.py          # FastAPI — POST /submit, GET /status
│   ├── extractor/
│   │   ├── main.py             # Orchestrator — coordinates analysis pipeline
│   │   ├── signature.py        # YARA + hash matching + ZIP extraction
│   │   ├── reputation.py       # VirusTotal, OTX, MalwareBazaar + circuit breaker
│   │   ├── context.py          # SPF/DKIM/DMARC, urgency markers, file type mismatch
│   │   ├── behavioral.py       # Sandbox stub (CAPE integration planned)
│   │   └── normalizer.py       # Raw features → component scores [0, 1]
│   ├── scoring/engine.py       # R = Σ wᵢ·Sᵢ with weight redistribution
│   ├── policy/rules.py         # Threshold classification + gray zone handling
│   └── audit/formatter.py      # CEF + JSON output for SIEM
├── tests/                      # pytest — 42 tests
├── yara_rules/default.yar      # Base YARA ruleset
└── alembic/                    # Database migrations
```

## Testing

```bash
make test          # Run all tests
make test-cov      # With coverage report
make lint          # Ruff linter
```

42 unit tests covering: scoring engine, policy rules, normalizer, context analysis, audit formatter.

## Configuration

Key environment variables (`.env`):

| Variable | Description | Default |
|----------|-------------|---------|
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka broker address | `kafka:9092` |
| `POSTGRES_HOST` / `POSTGRES_DB` | PostgreSQL connection | `postgres` / `emailrisk` |
| `REDIS_URL` | Redis URL for caching | `redis://redis:6379/0` |
| `API_KEY` | API authentication key | *(must change)* |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key | — |
| `ALIENVAULT_OTX_API_KEY` | AlienVault OTX API key | — |
| `WEIGHT_SIGNATURE` / `BEHAVIORAL` / `REPUTATION` / `CONTEXT` | Component weights | 0.20 / 0.40 / 0.25 / 0.15 |
| `THRESHOLD_LOW` / `THRESHOLD_HIGH` | Classification thresholds | 0.30 / 0.70 |

## License

MIT
