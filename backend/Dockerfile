# syntax=docker/dockerfile:1

# ---- Builder stage --------------------------------------------------------
FROM python:3.12-slim AS builder

# Install uv by copying the static binary from its official distroless image.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Install dependencies first (production only, no dev group) so this layer
# is cached independently of application code changes.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --no-install-project

# Now copy the application source and install the project itself.
COPY README.md ./README.md
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./alembic.ini

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev

# ---- Runtime stage ---------------------------------------------------------
FROM python:3.12-slim AS runtime

# Install curl for the HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Copy uv into the runtime image so `uv run` works without re-resolving deps.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

RUN groupadd --system app && useradd --system --gid app --create-home app

WORKDIR /app

COPY --from=builder --chown=app:app /opt/venv /opt/venv
COPY --from=builder --chown=app:app /build/app ./app
COPY --from=builder --chown=app:app /build/migrations ./migrations
COPY --from=builder --chown=app:app /build/alembic.ini ./alembic.ini
COPY --chown=app:app pyproject.toml ./

ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Run binaries directly from the prebuilt venv (on PATH) — no runtime re-sync.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
