.PHONY: up down build test lint migrate logs clean

# ── Docker ──
up:
	docker compose up -d --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

logs-%:
	docker compose logs -f $*

# ── Database ──
migrate:
	alembic upgrade head

migration:
	alembic revision --autogenerate -m "$(msg)"

# ── Testing ──
test:
	python -m pytest tests/ -v --tb=short

test-cov:
	python -m pytest tests/ -v --cov=shared --cov=services --cov-report=term-missing

# ── Linting ──
lint:
	ruff check shared/ services/ tests/
	ruff format --check shared/ services/ tests/

format:
	ruff check --fix shared/ services/ tests/
	ruff format shared/ services/ tests/

# ── Dev ──
install:
	pip install -e ".[dev]"

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
