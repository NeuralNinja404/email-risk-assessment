# Валідаційний план — Email Risk Assessment System

Перевірка коректності поточної імплементації 5-сервісного pipeline:
**Ingest → Extractor → Scoring → Policy → Audit**

---

## 1. Unit-тести бізнес-логіки

### 1.1 Scoring Engine (`services/scoring/engine.py`)
- [ ] R = 0 при всіх компонентах = 0
- [ ] R = 1 при всіх компонентах = 1
- [ ] Behavioral вага (0.40) домінує: S_beh=1.0, решта=0 → R ≈ 0.40
- [ ] Перерозподіл ваг при `beh_available=False`: w_beh=0, решта пропорційно
- [ ] Сума перерозподілених ваг = 1.0 (з точністю до float)
- [ ] Score clamped до [0, 1] при вхідних значеннях > 1
- [ ] Сценарій Medium Risk: S_sig=0.3, S_rep=0.4, S_ctx=0.6, beh=False → R ∈ [0.30, 0.70]

### 1.2 Policy Rules (`services/policy/rules.py`)
- [ ] R=0.10 → LOW / ALLOW, not gray
- [ ] R=0.50 → MEDIUM / HOLD_FOR_REVIEW, not gray
- [ ] R=0.85 → HIGH / QUARANTINE, not gray
- [ ] R=0.30 (точна границя) → MEDIUM (не LOW)
- [ ] R=0.70 (точна границя) → HIGH (не MEDIUM)
- [ ] R=0.29 → gray zone (±0.03 від low boundary)
- [ ] R=0.71 → gray zone (±0.03 від high boundary)
- [ ] R=0.0 → LOW / ALLOW
- [ ] R=1.0 → HIGH / QUARANTINE
- [ ] Explanation містить значення score

### 1.3 Normalizer (`services/extractor/normalizer.py`)
- [ ] Всі нульові features → S_sig=0, S_beh=0, S_rep=0, S_ctx=0
- [ ] High signature: f_sig1=1.0, f_sig2=1.0, f_sig3=0.8 → S_sig > 0.7
- [ ] hash_known_malicious=True додає бонус +0.3
- [ ] Бонус не перевищує 1.0 (clamp)
- [ ] S_beh=0 якщо sandbox_executed=False
- [ ] Всі scores обмежені діапазоном [0, 1]

### 1.4 Audit Formatter (`services/audit/formatter.py`)
- [ ] CEF починається з `CEF:0|EmailRisk|HybridAnalyzer|1.0|`
- [ ] Severity mapping: LOW→3, MEDIUM→6, HIGH→9
- [ ] CEF містить task_id, risk_score, decision, component scores
- [ ] JSON містить event_type, risk_score, decision, components dict, timestamp

---

## 2. Context Analysis (`services/extractor/context.py`)

### 2.1 Urgency Detection
- [ ] Нейтральний subject "Monthly report" → score=0, keywords=[]
- [ ] "URGENT: Verify Your Account" → score > 0
- [ ] Множинні маркери → score ≥ 0.4
- [ ] Українська: "ТЕРМІНОВО: Підтвердіть" → score > 0
- [ ] Subject без маркерів, але body має → все одно детектує *(зараз body не передається)*

### 2.2 Header Anomalies
- [ ] SPF=pass, DKIM=pass, DMARC=pass → score=0.0
- [ ] SPF=fail, DKIM=fail, DMARC=fail → score=1.0
- [ ] Reply-To домен ≠ sender домен → score > 0
- [ ] Порожні поля SPF/DKIM/DMARC → score=0 (не fail)
- [ ] Sender або reply_to = None → не crashає

### 2.3 File Type Mismatch
- [ ] report.pdf + application/pdf → 0.0 (match)
- [ ] report.pdf + application/x-dosexec → > 0.5 (mismatch)
- [ ] Невідоме розширення (.xyz) → 0.1

### 2.4 Format Risk
- [ ] .docx → 0.0 (safe)
- [ ] .iso → 1.0 (high risk)
- [ ] .exe → 0.7 (medium risk)
- [ ] .docm → 0.5 (macro-enabled)
- [ ] .abc (unknown) → 0.3 (default)

---

## 3. Signature Analysis (`services/extractor/signature.py`)

### 3.1 YARA сканування
- [ ] Файл без збігів → yara_matches=[], critical_count=0
- [ ] Файл зі збігами → yara_matches містить назви правил
- [ ] YARA бібліотека не встановлена → silent fallback, f_sig1=0, f_sig2=0
- [ ] Директорія правил не існує → logged warning, продовжує роботу
- [ ] Правила з syntax error → exception caught, logged, повертає []

### 3.2 MIME detection
- [ ] PDF файл → `application/pdf`
- [ ] python-magic не встановлена → fallback `application/octet-stream`
- [ ] Порожній файл → не crashає

### 3.3 ZIP extraction
- [ ] Звичайний ZIP → витягує внутрішні файли з SHA-256
- [ ] ZIP з .exe усередині → підвищує f_sig1 + f_sig2
- [ ] Вкладений ZIP (depth > 5) → зупиняється з warning
- [ ] ZIP bomb (ratio > 1000) → skip + warning
- [ ] Загальний розмір > 100MB → зупиняє розпаковку
- [ ] Невалідний ZIP → BadZipFile caught, повертає []
- [ ] Не-ZIP файл (.rar, .7z) → повертає [] (не підтримується)

### 3.4 Hash computation
- [ ] Повертає sha256,md5 для будь-якого контенту
- [ ] TLSH не встановлена → повертає порожній рядок

---

## 4. Reputation Analysis (`services/extractor/reputation.py`)

### 4.1 API клієнти (mock)
- [ ] VirusTotal: detection_ratio обчислюється правильно з malicious/total
- [ ] VirusTotal 404 → ratio=0.0
- [ ] OTX: pulse_count витягується з response
- [ ] MalwareBazaar: hash_not_found → 0.0; known → 1.0
- [ ] Domain reputation: malicious+suspicious/total

### 4.2 Caching (Redis mock)
- [ ] Перший запит → cache miss → API виклик → cache set
- [ ] Другий запит з тим же hash → cache hit → без API виклику
- [ ] Redis недоступний → silent fallback, API виклик без кешу

### 4.3 Circuit Breaker
- [ ] 3 послідовних failure → breaker OPEN
- [ ] Breaker OPEN → виклики повертають 0 без HTTP-запиту
- [ ] Через 300s → breaker HALF-OPEN → наступний запит тестує API

### 4.4 Fallback chain
- [ ] VT доступний → f_rep1 = vt_ratio
- [ ] VT недоступний, MalwareBazaar доступний → f_rep1 = mb_score
- [ ] Обидва недоступні, OTX доступний → f_rep1 з pulse_count
- [ ] Всі API недоступні → f_rep1=0, f_rep2=0, f_rep3=0

### 4.5 Порожні API keys
- [ ] virustotal_api_key="" → skip VT, return (0.0, False)
- [ ] alienvault_otx_api_key="" → skip OTX, return 0

---

## 5. Ingest Service (`services/ingest/main.py`)

### 5.1 Endpoint POST /api/v1/submit
- [ ] Валідний файл + metadata → 200, task_id повертається
- [ ] Порожній файл → 400
- [ ] Файл > 50MB → 413
- [ ] Невалідний email_metadata_json → 400
- [ ] Без API ключа → 401
- [ ] Невірний API ключ → 401
- [ ] Файл зберігається по шляху /data/attachments/{sha256}
- [ ] SHA-256 та MD5 обчислюються коректно
- [ ] Запис створюється в analysis_tasks з status=PENDING
- [ ] Повідомлення публікується в Kafka topic tasks.extract

### 5.2 Endpoint GET /api/v1/status/{task_id}
- [ ] Існуючий task → повертає поточний status
- [ ] Завершений task → повертає risk_score, risk_level, decision
- [ ] Неіснуючий task_id → 404
- [ ] Невалідний UUID → 400
- [ ] Без API ключа → 401

### 5.3 Rate Limiting
- [ ] Перевищення ліміту (>10/sec) → 429

---

## 6. End-to-End Pipeline

### 6.1 Happy Path
- [ ] Submit PDF → Extractor аналізує → Scoring обчислює R → Policy класифікує → Audit логує → status=COMPLETED
- [ ] Час обробки записується у processing_time_ms
- [ ] AuditLog запис містить CEF string + event_data JSON

### 6.2 Benign файл (очікуваний LOW risk)
- [ ] Чистий .docx файл + legitimate metadata (SPF=pass, DKIM=pass) → R < 0.30
- [ ] Decision = ALLOW

### 6.3 Malicious файл (очікуваний HIGH risk)
- [ ] ZIP з .exe + suspicious metadata (SPF=fail, subject="URGENT") → R ≥ 0.70
- [ ] Decision = QUARANTINE

### 6.4 Medium risk (gray zone)
- [ ] Файл з помірними ознаками → R ∈ [0.30, 0.70]
- [ ] Decision = HOLD_FOR_REVIEW

---

## 7. Kafka Pipeline

### 7.1 Черги
- [ ] Ingest публікує в `tasks.extract`
- [ ] Extractor публікує в `tasks.score`
- [ ] Scoring публікує в `tasks.policy`
- [ ] Policy публікує в `tasks.audit`

### 7.2 Consumer groups
- [ ] Кожен сервіс має свій group_id (extractor-group, scoring-group, policy-group, audit-group)
- [ ] auto_offset_reset=earliest — нові consumer'и отримують всі необроблені повідомлення

### 7.3 Обробка помилок
- [ ] Handler exception → logged + committed (не блокує чергу)
- [ ] Kafka недоступний → producer raise timeout після 30s

---

## 8. Database

### 8.1 Таблиці
- [ ] analysis_tasks створюється з усіма полями (id, file_sha256, status, email_metadata JSONB...)
- [ ] analysis_results створюється з усіма score полями + feature_vector JSONB
- [ ] audit_logs створюється з cef_string + event_data JSONB
- [ ] Індекси існують: file_sha256, status, risk_level, task_id

### 8.2 Стани задачі
- [ ] PENDING → EXTRACTING → SCORING → POLICY → COMPLETED (happy path)
- [ ] Кожен сервіс оновлює status коректно
- [ ] FAILED стан — перевірити що встановлюється при exception

---

## 9. Configuration Validation

### 9.1 Ваги
- [ ] weight_signature + weight_behavioral + weight_reputation + weight_context = 1.0
- [ ] Всі ваги > 0
- [ ] weight_behavioral > weight_signature (за дизайном: поведінка > сигнатури)

### 9.2 Пороги
- [ ] threshold_low < threshold_high
- [ ] gray_zone_margin > 0 та < (threshold_high - threshold_low) / 2
- [ ] Значення за замовчуванням: 0.30, 0.70, 0.03

### 9.3 Секрети
- [ ] API_KEY ≠ "changeme-generate-a-real-key" (дефолт)
- [ ] .env файл існує і заповнений

---

## 10. Docker / Infrastructure

### 10.1 Контейнери
- [ ] `docker compose up` піднімає всі 8 сервісів без помилок
- [ ] Kafka healthcheck проходить
- [ ] PostgreSQL healthcheck проходить
- [ ] Redis healthcheck проходить
- [ ] Kafka topics створюються (tasks.extract, tasks.score, tasks.policy, tasks.audit)

### 10.2 Volumes
- [ ] pg_data — persistent storage для PostgreSQL
- [ ] redis_data — persistent storage для Redis
- [ ] attachment_data — shared між ingest (RW) і extractor (RO)

### 10.3 Non-root containers
- [ ] Всі application services працюють під `appuser`, не root

---

## 11. Відомі обмеження (перевірити що задокументовані)

- [ ] Behavioral компонент — заглушка (S_beh=0 завжди)
- [ ] Sandbox (CAPE) не інтегрований
- [ ] MISP API клієнт не реалізований
- [ ] ZIP — єдиний підтримуваний контейнер (без RAR, 7z, ISO)
- [ ] Немає dedup cache (той самий файл аналізується повторно)
- [ ] Foreign key між analysis_results.task_id і analysis_tasks.id відсутній
- [ ] Немає unique constraint на task_id в analysis_results
- [ ] Ваги нормалізатора (всередині S_sig, S_rep, S_ctx) hardcoded
