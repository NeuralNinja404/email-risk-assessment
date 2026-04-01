# Email Risk Assessment

Гібридний метод інтегральної оцінки ризику вкладень електронної пошти в корпоративному середовищі.

Мікросервісна система для автоматичного аналізу вкладень електронної пошти з обчисленням інтегральної оцінки ризику на основі чотирьох компонентів: сигнатурного, поведінкового, репутаційного та контекстного.

## Архітектура

```
┌─────────┐    Kafka     ┌────────────┐   Kafka    ┌─────────┐   Kafka    ┌────────┐   Kafka    ┌───────┐
│ Ingest  │──────────────▶│ Extractor  │───────────▶│ Scoring │───────────▶│ Policy │───────────▶│ Audit │
│ (HTTP)  │ tasks.extract │ (Features) │ tasks.score│  (R)    │tasks.policy│(Decision)│tasks.audit│ (SIEM)│
└─────────┘              └────────────┘            └─────────┘           └────────┘            └───────┘
     │                        │                        │                     │                     │
     └────────────────────────┴────────────────────────┴─────────────────────┴─────────────────────┘
                                            PostgreSQL + Redis
```

### Сервіси

| Сервіс | Опис | Порт |
|--------|------|------|
| **Ingest** | FastAPI HTTP API — приймає вкладення та email-метадані | 8000 |
| **Extractor** | Аналіз features: YARA, reputation APIs, контекст email | — |
| **Scoring** | Обчислює R = w₁·S_sig + w₂·S_beh + w₃·S_rep + w₄·S_ctx | — |
| **Policy** | Класифікація: LOW / MEDIUM / HIGH → ALLOW / HOLD / QUARANTINE | — |
| **Audit** | CEF + JSON логування для SIEM | — |

## Формула інтегральної оцінки ризику

```
R = w₁·S_sig + w₂·S_beh + w₃·S_rep + w₄·S_ctx
```

| Компонент | Вага | Опис |
|-----------|------|------|
| S_sig | 0.20 | Сигнатурний аналіз (YARA, hash matching) |
| S_beh | 0.40 | Поведінковий аналіз (sandbox) |
| S_rep | 0.25 | Репутаційний аналіз (VirusTotal, OTX, MalwareBazaar) |
| S_ctx | 0.15 | Контекстний аналіз (SPF/DKIM/DMARC, urgency markers) |

Класифікація:
- **LOW** (R < 0.30) → дозволити доставку
- **MEDIUM** (0.30 ≤ R < 0.70) → утримати для перевірки аналітиком
- **HIGH** (R ≥ 0.70) → карантин + інцидент SOC

## Технологічний стек

- **Python 3.12+**
- **FastAPI** — HTTP API (Ingest)
- **Apache Kafka** — message broker між сервісами
- **PostgreSQL 16** — зберігання задач, результатів, аудит-логів
- **Redis 7** — кешування reputation API відповідей
- **YARA** — сигнатурне сканування
- **Docker Compose** — оркестрація

## Швидкий старт

### Вимоги

- Docker + Docker Compose
- Python 3.12+ (для локальної розробки)

### Запуск через Docker

```bash
cp .env.example .env
# Заповнити API ключі у .env (VirusTotal, OTX та ін.)

docker compose up -d --build
```

Сервіс буде доступний на `http://localhost:8000`.

### Локальна розробка

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Запустити інфраструктуру
docker compose up -d kafka postgres redis kafka-init

# Запустити тести
make test
```

## API

### Відправити вкладення на аналіз

```bash
curl -X POST http://localhost:8000/api/v1/submit \
  -H "X-API-Key: YOUR_KEY" \
  -F "file=@attachment.pdf" \
  -F 'email_metadata_json={"sender":"user@example.com","sender_domain":"example.com","subject":"Report","spf_result":"pass","dkim_result":"pass","dmarc_result":"pass"}'
```

Відповідь:
```json
{"task_id": "550e8400-e29b-41d4-a716-446655440000", "status": "PENDING", "message": "Attachment accepted for analysis"}
```

### Перевірити статус

```bash
curl http://localhost:8000/api/v1/status/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-Key: YOUR_KEY"
```

Відповідь:
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

## Структура проєкту

```
email-risk-assessment/
├── docker-compose.yml          # Kafka, PostgreSQL, Redis + 5 сервісів
├── pyproject.toml              # Залежності та конфігурація
├── Makefile                    # make up / test / lint / migrate
├── .env.example                # Шаблон конфігурації
├── shared/                     # Спільна бібліотека
│   ├── schemas.py              # Pydantic моделі
│   ├── config.py               # Налаштування (pydantic-settings)
│   ├── mq.py                   # Kafka producer/consumer helpers
│   ├── db.py                   # SQLAlchemy async engine
│   ├── models.py               # ORM моделі (AnalysisTask, AnalysisResult, AuditLog)
│   └── logging.py              # Structured logging (structlog)
├── services/
│   ├── ingest/main.py          # FastAPI — POST /submit, GET /status
│   ├── extractor/
│   │   ├── main.py             # Orchestrator — координує аналіз
│   │   ├── signature.py        # YARA + hash + ZIP extraction
│   │   ├── reputation.py       # VirusTotal, OTX, MalwareBazaar + circuit breaker
│   │   ├── context.py          # SPF/DKIM/DMARC, urgency markers, file type mismatch
│   │   ├── behavioral.py       # Sandbox stub (CAPE integration planned)
│   │   └── normalizer.py       # Feature → component scores [0, 1]
│   ├── scoring/engine.py       # R = Σ wᵢ·Sᵢ з перерозподілом ваг
│   ├── policy/rules.py         # Threshold classification + gray zone
│   └── audit/formatter.py      # CEF + JSON для SIEM
├── tests/                      # pytest — 42 тести
├── yara_rules/default.yar      # Базові YARA правила
└── alembic/                    # Database migrations
```

## Тестування

```bash
make test          # Запуск всіх тестів
make test-cov      # З coverage report
make lint          # Ruff linter
```

42 unit-тести покривають: scoring engine, policy rules, normalizer, context analysis, audit formatter.

## Конфігурація

Основні змінні середовища (`.env`):

| Змінна | Опис | За замовч. |
|--------|------|-----------|
| `KAFKA_BOOTSTRAP_SERVERS` | Адреса Kafka broker | `kafka:9092` |
| `POSTGRES_HOST` / `POSTGRES_DB` | PostgreSQL підключення | `postgres` / `emailrisk` |
| `REDIS_URL` | Redis URL для кешування | `redis://redis:6379/0` |
| `API_KEY` | Ключ аутентифікації API | *(обов'язково змінити)* |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key | — |
| `ALIENVAULT_OTX_API_KEY` | AlienVault OTX API key | — |
| `WEIGHT_SIGNATURE` / `BEHAVIORAL` / `REPUTATION` / `CONTEXT` | Ваги компонентів | 0.20 / 0.40 / 0.25 / 0.15 |
| `THRESHOLD_LOW` / `THRESHOLD_HIGH` | Пороги класифікації | 0.30 / 0.70 |

## Ліцензія

MIT
