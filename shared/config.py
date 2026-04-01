from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Kafka ──
    kafka_bootstrap_servers: str = "kafka:9092"

    # ── PostgreSQL ──
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "emailrisk"
    postgres_user: str = "emailrisk"
    postgres_password: str = "emailrisk_secret"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # ── Redis ──
    redis_url: str = "redis://redis:6379/0"

    # ── Ingest ──
    api_key: str = "changeme-generate-a-real-key"
    attachment_storage_path: str = "/data/attachments"
    max_file_size_mb: int = 50
    ingest_rate_limit: str = "10/second"

    # ── Scoring Weights ──
    weight_signature: float = 0.20
    weight_behavioral: float = 0.40
    weight_reputation: float = 0.25
    weight_context: float = 0.15

    # ── Policy Thresholds ──
    threshold_low: float = 0.30
    threshold_high: float = 0.70
    gray_zone_margin: float = 0.03

    # ── External APIs ──
    virustotal_api_key: str = ""
    alienvault_otx_api_key: str = ""
    misp_url: str = ""
    misp_api_key: str = ""

    # ── Sandbox ──
    cape_api_url: str = ""
    cape_timeout_quick: int = 120
    cape_timeout_extended: int = 300

    # ── Logging ──
    log_level: str = "INFO"
    log_format: str = "json"


settings = Settings()
