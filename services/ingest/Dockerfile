FROM python:3.11-slim AS builder
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY shared/ shared/
COPY services/ingest/ services/ingest/
COPY services/__init__.py services/__init__.py

RUN useradd -r -s /bin/false appuser && mkdir -p /data/attachments && chown appuser:appuser /data/attachments
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s CMD python -c "import httpx; httpx.get('http://localhost:8000/api/v1/health').raise_for_status()" || exit 1

CMD ["uvicorn", "services.ingest.main:app", "--host", "0.0.0.0", "--port", "8000"]
