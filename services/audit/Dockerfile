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
COPY services/__init__.py services/__init__.py
COPY services/audit/ services/audit/

RUN useradd -r -s /bin/false appuser
USER appuser

CMD ["python", "-m", "services.audit.main"]
