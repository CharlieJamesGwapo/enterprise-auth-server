# Enterprise Authentication Server

A production-grade authentication and authorization service built with FastAPI, designed as a
standalone backend that other applications can delegate identity, session, and access-control
concerns to. It provides secure user registration and login, JWT-based sessions delivered via
httpOnly cookies, and role-based access control (RBAC), all built on an async SQLAlchemy +
PostgreSQL data layer with Redis for rate limiting and token state.

## Status: Foundation slice

This repository currently contains the **foundation slice** plus **two-factor authentication
(2FA)**, **session management**, and **email & notifications**: core authentication, RBAC,
security middleware, TOTP-based 2FA, per-login session tracking with revocation, transactional
email (verification, password reset, change-email, new-device alerts), and the supporting
infrastructure (Docker, CI, migrations). It is meant to be a solid base that later slices build
on top of. Planned future slices include:

- OAuth / social login providers (Google/GitHub)
- Full user profile + avatar, change-password, delete-account
- Admin dashboard
- Audit logs persisted to the database
- API keys for service-to-service auth
- Notifications beyond email
- Pagination / filtering

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
# and a real ENCRYPTION_KEY for 2FA secret storage, e.g.:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

docker compose up --build
```

See `backend/.env.example` for the full list of configuration options. In addition to the core
settings, the following env vars configure 2FA:

| Variable | Default | Description |
|----------|---------|--------------|
| `ENCRYPTION_KEY` | — (required) | Fernet key used to encrypt TOTP secrets at rest |
| `PRE_AUTH_TOKEN_EXPIRE_MINUTES` | `5` | Lifetime of the `pre_auth_token` issued after step 1 of a 2FA login |
| `TWO_FACTOR_ISSUER` | `Enterprise Auth Server` | Issuer name shown in the authenticator app |
| `TOTP_VALID_WINDOW` | `1` | Number of TOTP time-steps of clock drift tolerated on either side |
| `BACKUP_CODE_COUNT` | `10` | Number of recovery codes generated per set |
| `TWO_FA_RATE_LIMIT_PER_MINUTE` | `5` | Rate limit for 2FA verification attempts |
| `TWO_FA_MAX_FAILURES` | `5` | Number of failed attempts before lockout |

The following env vars configure session management:

| Variable | Default | Description |
|----------|---------|--------------|
| `SESSION_IDLE_TIMEOUT_MINUTES` | `30` | Minutes of inactivity before a session is considered expired |
| `SESSION_ABSOLUTE_EXPIRE_HOURS` | `720` | Maximum lifetime of a session regardless of activity |
| `SESSION_ACTIVITY_THROTTLE_SECONDS` | `10` | Minimum interval between `last_activity_at` updates, to avoid a write on every request |

The following env vars configure transactional email:

| Variable | Default | Description |
|----------|---------|--------------|
| `EMAIL_BACKEND` | `console` | Delivery backend: `smtp` (real delivery via `aiosmtplib`), `console` (logs the message, default for local dev), or `memory` (in-process outbox used by the test suite) |
| `EMAIL_HOST` | `localhost` | SMTP host (used when `EMAIL_BACKEND=smtp`) |
| `EMAIL_PORT` | `1025` | SMTP port (used when `EMAIL_BACKEND=smtp`) |
| `EMAIL_USERNAME` | — | SMTP auth username |
| `EMAIL_PASSWORD` | — | SMTP auth password |
| `EMAIL_USE_TLS` | `false` | Whether to use TLS for the SMTP connection |
| `EMAIL_FROM` | `no-reply@enterprise-auth.local` | From address on outgoing emails |
| `EMAIL_FROM_NAME` | `Enterprise Auth Server` | From display name on outgoing emails |
| `APP_BASE_URL` | `http://localhost:3000` | Base URL used to build links embedded in emails |
| `EMAIL_VERIFICATION_EXPIRE_HOURS` | `24` | Lifetime of an email verification token |
| `PASSWORD_RESET_EXPIRE_MINUTES` | `30` | Lifetime of a password reset token |
| `EMAIL_CHANGE_EXPIRE_HOURS` | `24` | Lifetime of an email-change confirmation token |

For local dev with `EMAIL_BACKEND=smtp`, an SMTP catcher such as [MailHog](https://github.com/mailhog/MailHog) is a convenient way to view sent emails without a real mail provider; it's an optional dev tool and isn't wired into `docker-compose.yml`.

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
| POST   | `/api/v1/auth/login/otp` | Complete login with a TOTP code, using the `pre_auth_token` from the initial login |
| POST   | `/api/v1/auth/login/recovery-code` | Complete login with a recovery code, using the `pre_auth_token` from the initial login |
| POST   | `/api/v1/auth/2fa/setup` | Start 2FA enrollment; returns provisioning URI, QR code, and secret (not yet active) |
| POST   | `/api/v1/auth/2fa/verify` | Confirm setup with a TOTP code; activates 2FA |
| GET    | `/api/v1/auth/2fa/status` | Get 2FA status: enabled, verified_at, recovery codes remaining |
| GET    | `/api/v1/auth/2fa/qrcode` | Serve the pending setup's QR code as a PNG image |
| POST   | `/api/v1/auth/2fa/disable` | Disable 2FA (requires password + OTP); deletes the secret and all recovery codes |
| POST   | `/api/v1/auth/2fa/recovery-codes` | Generate recovery codes (requires password + OTP); shown in plaintext once |
| POST   | `/api/v1/auth/2fa/recovery-codes/regenerate` | Replace recovery codes (requires password + OTP); shown in plaintext once |
| GET    | `/api/v1/sessions`       | List active sessions for the current user   |
| GET    | `/api/v1/sessions/{session_id}` | Fetch a single session owned by the current user |
| DELETE | `/api/v1/sessions/{session_id}` | Revoke a specific session (ownership enforced) |
| POST   | `/api/v1/sessions/logout` | Revoke the current session and clear session cookies |
| POST   | `/api/v1/sessions/logout-all` | Revoke every session for the user, including the current one, and clear session cookies |
| GET    | `/api/v1/users/last-login` | Details of the user's previous login       |
| POST   | `/api/v1/auth/verify-email` | Confirm an email address using the token from the verification email |
| POST   | `/api/v1/auth/resend-verification` | Resend the verification email (requires authentication) |
| POST   | `/api/v1/auth/forgot-password` | Request a password reset email; always returns 200 to avoid account enumeration |
| POST   | `/api/v1/auth/reset-password` | Set a new password using a reset token; sends a password-changed alert |
| POST   | `/api/v1/auth/change-email` | Request an email change (requires authentication + password); sends a confirmation link to the new address |
| POST   | `/api/v1/auth/confirm-email-change` | Apply a pending email change using the token from the confirmation email |
| GET    | `/api/v1/health`        | Liveness check                              |
| GET    | `/api/v1/ready`         | Readiness check (verifies DB and Redis connectivity) |

## Security

- **Password hashing:** Argon2id
- **Password strength policy:** enforced on registration and password reset — minimum 8
  characters, requires a lowercase letter, an uppercase letter, a digit, and a symbol, and
  rejects a small denylist of common passwords
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

### Two-Factor Authentication (2FA)

The server supports TOTP-based two-factor authentication ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)),
compatible with standard authenticator apps such as Google Authenticator, Microsoft
Authenticator, Authy, 1Password, and Bitwarden.

**Enabling 2FA:**

1. `POST /api/v1/auth/2fa/setup` with `{"password": "..."}` returns a `provisioning_uri`,
   `qr_code_base64`, and the raw `secret`. 2FA is **not yet active** at this point.
2. The user scans the QR code (or enters the secret manually) in their authenticator app.
3. `POST /api/v1/auth/2fa/verify` with `{"otp": "123456"}` confirms the code and activates 2FA,
   returning `{"success": true}`.

**Logging in with 2FA enabled** is a two-step flow:

1. `POST /api/v1/auth/login` returns `{"otp_required": true, "pre_auth_token": "..."}` with
   **no session cookies set**. No JWT is issued until the second factor is verified.
2. The client then calls either:
   - `POST /api/v1/auth/login/otp` with `{"pre_auth_token": "...", "otp": "123456"}`, or
   - `POST /api/v1/auth/login/recovery-code` with
     `{"pre_auth_token": "...", "recovery_code": "ABCD-EFGH-IJKL"}`

   to receive the real session (httpOnly cookies), as in the standard login flow.

**Recovery codes:** 10 single-use codes are generated in the format `XXXX-XXXX-XXXX` (12
alphanumeric characters grouped with dashes). They are shown in plaintext exactly once and
stored server-side only as Argon2 hashes. `POST /api/v1/auth/2fa/recovery-codes` (requires
`{password, otp}`) generates them, and `POST /api/v1/auth/2fa/recovery-codes/regenerate`
(requires `{password, otp}`) replaces the existing set.

**Security properties:**

- TOTP secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC), keyed from the
  `ENCRYPTION_KEY` environment variable
- The secret is never exposed again after the initial setup response
- OTP comparison is constant-time (via `pyotp`/`hmac`)
- OTP replay is prevented — used codes are tracked in Redis for their validity window
- Per-user rate limiting and lockout on repeated 2FA failures
- All 2FA events are audit-logged: `2fa_setup_started`, `2fa_enabled`, `2fa_disabled`, recovery
  code generation/use, and login challenges/successes

**Data model:** two new tables, applied via Alembic migration:

- `two_factor_auth` — `id`, `user_id`, `encrypted_secret`, `enabled`, `verified_at`,
  `created_at`, `updated_at`
- `backup_codes` — `id`, `user_id`, `hashed_code`, `used_at`, `created_at`

### Session Management

Every successful login creates an independent session row rather than treating the JWT alone as
the source of truth. The access and refresh JWTs carry the session id (`sid` claim), and
`get_current_user` validates the session on every authenticated request — checking that it
hasn't been revoked, hasn't gone idle, and hasn't hit its absolute expiry — and updates the
session's activity timestamp. Because of this, server-side revocation takes effect immediately,
even though the JWT itself is still cryptographically valid until it expires.

**Device and location info:** device, browser, and OS are parsed from the request's User-Agent
using the `user-agents` library. The client IP is captured (honoring `X-Forwarded-For` when
present). Country and city are resolved via a pluggable Geo-IP resolver that reads CDN-supplied
headers such as `CF-IPCountry`; no MaxMind database is bundled, so this is offline-safe and the
fields are simply `null` when the information isn't available. Known limitation: Brave cannot be
distinguished from Chrome by User-Agent alone.

**Listing and managing sessions:**

- `GET /api/v1/sessions` returns the current user's active sessions, each including `device`,
  `device_type`, `browser`, `browser_version`, `os`, `os_version`, `ip`, `country`, `city`,
  `login_at`, `last_activity`, a `current` flag, and `status`.
- `GET /api/v1/sessions/{session_id}` fetches a single session owned by the current user.
- `DELETE /api/v1/sessions/{session_id}` revokes a specific session; ownership is enforced.
- `POST /api/v1/sessions/logout` revokes the current session and clears the session cookies.
- `POST /api/v1/sessions/logout-all` revokes every session for the user, including the current
  one, and clears the session cookies.
- `GET /api/v1/users/last-login` returns details of the user's previous login:
  `previous_login_at`, `previous_login_ip`, `previous_device`, `previous_browser`.

**Security properties:**

- Refresh-token rotation keeps the same session bound across renewals — the rotated JTI is
  stored on the session row rather than starting a new session
- Revoked or expired sessions blacklist their refresh JTI in Redis
- A per-session revocation flag is cached in Redis for fast checks on every request
- Sessions enforce both idle timeout and absolute expiration
- New-device-login detection emits an audit event and triggers a new-device sign-in alert email
  (see [Email & Notifications](#email--notifications) below)
- Redis is treated as a cache; PostgreSQL is the authoritative store for session state

**Data model:** one new table, applied via Alembic migration:

- `sessions` — `id`, `user_id`, `refresh_token_id`, `session_uuid`, `device_name`, `device_type`,
  `browser`, `browser_version`, `operating_system`, `operating_system_version`, `user_agent`,
  `ip_address`, `country`, `city`, `login_at`, `last_activity_at`, `logout_at`, `expires_at`,
  `logout_reason`, `is_current`, `is_active`, `request_count`, `created_at`, `updated_at`

### Email & Notifications

Transactional email is implemented with pluggable backends selected by `EMAIL_BACKEND`: `smtp`
(real delivery via `aiosmtplib` — e.g. MailHog in dev, a real SMTP provider in prod), `console`
(logs the message instead of sending it; default for local dev), and `memory` (an in-process
outbox used by the test suite to assert on sent mail). Emails are sent on FastAPI
`BackgroundTasks`, so request/response cycles never block on SMTP.

**Emails sent:**

- Welcome email, on registration
- Email verification, on registration and on resend
- Password reset
- Password-changed notification, after a successful reset
- Email-change confirmation, sent to the new address
- New-device sign-in alert, wired from the session slice's new-device detection

**Endpoints:** see [API endpoints](#api-endpoints) — `verify-email`, `resend-verification`,
`forgot-password`, `reset-password`, `change-email`, and `confirm-email-change`.

**Security properties:**

- Email tokens are single-use, high-entropy (`secrets.token_urlsafe`), and stored server-side
  only as SHA-256 hashes — the raw token appears only in the email itself
- Tokens expire: verification after `EMAIL_VERIFICATION_EXPIRE_HOURS` (24h), password reset
  after `PASSWORD_RESET_EXPIRE_MINUTES` (30m), email-change after `EMAIL_CHANGE_EXPIRE_HOURS`
  (24h)
- Only one active token per purpose — a new request supersedes the previous one
- `POST /api/v1/auth/forgot-password` is enumeration-safe: it always returns 200 regardless of
  whether the account exists
- `POST /api/v1/auth/confirm-email-change` re-checks that the new address is still available at
  confirmation time, not just at request time

**Data model:** one new table, applied via Alembic migration:

- `email_tokens` — `id`, `user_id`, `token_hash`, `purpose`, `new_email`, `expires_at`,
  `used_at`, `created_at`, `updated_at`

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
│   │   │       ├── auth.py        # register/login/refresh/logout/me, 2FA, email verification,
│   │   │       │                  # password reset, change-email
│   │   │       ├── health.py      # /health, /ready
│   │   │       ├── sessions.py    # list/get/revoke sessions, logout, logout-all
│   │   │       └── users.py       # /users (RBAC-protected), /users/last-login
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
