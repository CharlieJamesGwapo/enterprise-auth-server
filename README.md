# Enterprise Authentication Server

A production-grade authentication and authorization service built with FastAPI, designed as a
standalone backend that other applications can delegate identity, session, and access-control
concerns to. It provides secure user registration and login, JWT-based sessions delivered via
httpOnly cookies, and role-based access control (RBAC), all built on an async SQLAlchemy +
PostgreSQL data layer with Redis for rate limiting and token state.

## Status: Foundation slice

This repository currently contains the **foundation slice**: core authentication, RBAC,
security middleware, and the supporting infrastructure (Docker, CI, migrations). It is meant to
be a solid base that later slices build on top of. Planned future slices include:

- OAuth / social login providers
- Two-factor authentication (2FA)
- Session management (list/revoke active sessions)
- Transactional email (verification, password reset)
- Admin API (user/role management beyond the basic RBAC example)
- Audit logs
- API keys for service-to-service auth
- Notifications

None of the above are implemented yet — this README describes only what exists today.

## Tech stack

- **Framework:** FastAPI (async)
- **Language:** Python 3.12
- **Database:** PostgreSQL 16, accessed via SQLAlchemy 2.0 (async) and `asyncpg`
- **Migrations:** Alembic
- **Cache / rate limiting store:** Redis 7
- **Auth:** JWT (PyJWT), Argon2id password hashing (`argon2-cffi` / `passlib`)
- **Dependency management:** [`uv`](https://github.com/astral-sh/uv)
- **Reverse proxy:** Nginx
- **Containerization:** Docker / Docker Compose
- **CI:** GitHub Actions
- **Testing:** pytest, pytest-asyncio, httpx, factory-boy, fakeredis

## Architecture overview

The application follows a clean, layered architecture:

```
api → services → repositories → models
```

- **`app/api`** — FastAPI routers. Handles HTTP concerns (request/response schemas, status
  codes, dependency injection) and delegates business logic to services.
- **`app/services`** — Business logic (authentication flow, token issuance, rate limiting).
  Framework-agnostic where possible.
- **`app/repositories`** — Data access layer. Encapsulates SQLAlchemy queries behind a
  repository interface so services don't talk to the ORM directly.
- **`app/models`** — SQLAlchemy ORM models (`User`, `Role`, `Permission`, and their
  associations).

Supporting layers: `app/core` (config, security primitives, cookies, exceptions, logging),
`app/db` (session/engine setup), `app/redis` (Redis client), `app/middleware` (security headers,
rate limiting), and `app/dependencies` (FastAPI dependency providers, e.g. current user,
permission checks).

## Quick start with Docker

```bash
cp backend/.env.example backend/.env
# edit backend/.env and set a real SECRET_KEY, e.g.:
#   openssl rand -hex 32

docker compose up --build
```

Once the stack is up:

- App: http://localhost
- API docs (Swagger UI): http://localhost/docs

The `api` service automatically runs `alembic upgrade head` before starting Uvicorn, so the
database schema is created/updated on startup. Nginx listens on port 80 and proxies to the
FastAPI app on port 8000, forwarding `X-Forwarded-For` (used by the app for rate-limiting by
client IP), `X-Real-IP`, and `X-Forwarded-Proto`.

## Local development

This project uses [`uv`](https://github.com/astral-sh/uv) for dependency management.

```bash
cd backend
uv sync --group dev
uv run pytest
```

Tests need **no Postgres or Redis** — they run against SQLite (via `aiosqlite`) and
`fakeredis`, so the full test suite runs standalone with no external services.

Other useful commands (see `backend/Makefile`):

```bash
make install    # uv sync --group dev
make dev        # run the app with autoreload
make test       # run pytest
make lint       # ruff check + ruff format --check
make format     # ruff format + ruff check --fix
make migrate    # alembic upgrade head
make revision m="add some_table"   # alembic revision --autogenerate
```

## API endpoints

| Method | Path                | Description                                   |
|--------|---------------------|------------------------------------------------|
| POST   | `/api/v1/auth/register` | Register a new user                        |
| POST   | `/api/v1/auth/login`    | Log in, sets access/refresh cookies        |
| POST   | `/api/v1/auth/refresh`  | Rotate the access token using the refresh cookie |
| POST   | `/api/v1/auth/logout`   | Log out, revokes/blacklists the refresh token |
| GET    | `/api/v1/auth/me`       | Get the current authenticated user          |
| GET    | `/api/v1/users`         | List users (requires `manage_users` permission) |
| GET    | `/api/v1/health`        | Liveness check                              |
| GET    | `/api/v1/ready`         | Readiness check (verifies DB and Redis connectivity) |

## Security

- **Password hashing:** Argon2id
- **Token delivery:** access and refresh JWTs are set as httpOnly, Secure cookies (never
  exposed to client-side JavaScript)
- **Refresh token rotation:** each refresh issues a new refresh token; used/superseded tokens
  are blacklisted in Redis
- **CSRF protection:** double-submit cookie pattern for state-changing requests
- **Rate limiting:** configurable per-minute limits, with a stricter limit on auth endpoints
- **Brute-force protection:** account lockout after a configurable number of failed login
  attempts, for a configurable lockout window
- **Security headers:** applied via middleware (e.g. `X-Content-Type-Options`,
  `X-Frame-Options`, and related hardening headers)
- **CORS:** explicit, configurable allow-list of origins (no wildcard by default)

## Testing

```bash
cd backend
uv run pytest
```

The test suite covers authentication flows, RBAC/permission enforcement, and security behavior
(see `backend/tests/test_auth.py`, `backend/tests/test_rbac.py`, and
`backend/tests/test_security.py`). Tests run against an in-memory/SQLite database and
`fakeredis`, so no Docker services are required to run them locally or in CI.

## Project structure

```
enterprise-auth-server/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── router.py          # aggregates v1 routers
│   │   │   └── v1/
│   │   │       ├── auth.py        # register/login/refresh/logout/me
│   │   │       ├── health.py      # /health, /ready
│   │   │       └── users.py       # /users (RBAC-protected)
│   │   ├── core/                  # config, security, cookies, exceptions, logging
│   │   ├── db/                    # engine/session setup, seed data
│   │   ├── dependencies/          # DI providers (current user, permissions, db, redis)
│   │   ├── middleware/            # rate limiting, security headers
│   │   ├── models/                # User, Role, Permission (+ associations)
│   │   ├── redis/                 # Redis client
│   │   ├── repositories/          # data access layer
│   │   ├── schemas/                # Pydantic request/response models
│   │   ├── services/               # auth logic, token issuance, rate limiting
│   │   └── main.py                 # FastAPI app factory / entrypoint
│   ├── migrations/                 # Alembic migrations
│   ├── tests/                      # pytest suite (SQLite + fakeredis)
│   ├── alembic.ini
│   ├── Dockerfile
│   ├── Makefile
│   ├── pyproject.toml
│   └── .env.example
├── docker/
│   └── nginx/
│       └── nginx.conf
├── docker-compose.yml
└── .github/
    └── workflows/
        └── ci.yml
```
