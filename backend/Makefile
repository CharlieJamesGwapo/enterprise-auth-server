.PHONY: install dev test lint format check install-hooks migrate revision up down

install:
	uv sync --group dev

# Run the exact checks CI would run (lint + format + tests). Use this locally
# while GitHub Actions is unavailable.
check: lint test

# Install a git pre-push hook that runs `make check` before every push.
install-hooks:
	@printf '#!/bin/sh\ncd "$$(git rev-parse --show-toplevel)/backend" && make check\n' \
		> ../.git/hooks/pre-push
	@chmod +x ../.git/hooks/pre-push
	@echo "pre-push hook installed (runs: make check)"

dev:
	uv run uvicorn app.main:app --reload

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff format .
	uv run ruff check --fix .

migrate:
	uv run alembic upgrade head

revision:
	uv run alembic revision --autogenerate -m "$(m)"

up:
	docker compose up --build

down:
	docker compose down
