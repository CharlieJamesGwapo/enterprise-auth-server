# Enterprise Authentication Server — Foundation Slice Design

**Date:** 2026-07-14
**Status:** Approved (foundation slice)
**Author:** Backend engineering

## Context

The full brief describes ~10 independent subsystems (core auth, user management,
email, OAuth, 2FA, sessions, RBAC, admin API, audit logs, API keys, notifications)
plus infra, CI, and >90% test coverage. Building all of it in one pass produces
code that looks complete but is broken at the integration seams.

Decision: **decompose**. This spec covers only the **foundation slice** — a real,
running, tested core that later feature slices layer onto. Each remaining subsystem
gets its own spec → plan → implementation cycle.

## Decisions (locked)

- **Token transport:** access + refresh tokens in httpOnly, Secure, SameSite=Lax
  cookies. CSRF handled via double-submit token. (Matches "Secure Cookies + CSRF".)
- **Refresh strategy:** rotation on every refresh; old token's JTI blacklisted in
  Redis until natural expiry (token revocation / blacklist).
- **Password hashing:** Argon2id (argon2-cffi via passlib).
- **Tooling:** uv (deps/venv) + ruff (lint+format).
- **DB access:** async SQLAlchemy 2.0 + Alembic. No raw SQL. UUID PKs via a
  cross-dialect GUID type (native `UUID` on Postgres, `CHAR(36)` on SQLite).
- **Test infra:** SQLite (aiosqlite) + fakeredis, so `pytest` runs with zero
  external services locally and in CI. Production runs Postgres + Redis.
- **Repo:** private GitHub repo pushed via `gh`.

## Scope — IN this slice

- Clean-architecture FastAPI skeleton: `api → services → repositories → models`,
  plus `core`, `schemas`, `dependencies`, `middleware`. Routes hold zero business
  logic; services own logic; repositories own DB access.
- Docker Compose: Postgres + Redis + FastAPI (uvicorn) + Nginx reverse proxy.
  One command up (`docker compose up`). Not verifiable on this machine (no Docker);
  code is written to spec.
- Models: `users`, `roles`, `permissions`, `role_permissions`, `user_roles`.
  Seeded 4 roles (super_admin, admin, staff, user) and 5 permissions
  (manage_users, manage_roles, manage_permissions, view_dashboard, manage_api_keys).
- Auth flows: register, login, logout, refresh (rotation + Redis revocation),
  current user (`/me`).
- Security: Argon2, security headers, CORS, CSRF double-submit, Redis rate limiting
  on auth endpoints, brute-force lockout counter in Redis.
- RBAC: `require_permission(...)` FastAPI dependency guard used by all future
  protected endpoints.
- Structured JSON logging; clean centralized exception handling.
- Alembic initial migration.
- Pytest (async) + Factory Boy + Faker covering auth + RBAC + security. GitHub
  Actions: ruff lint + pytest + docker build.

## Scope — NOT in this slice (future specs)

OAuth (Google/GitHub) + linking · TOTP 2FA + backup codes · session/device tracking ·
full profile + avatar upload · email delivery (7 templates) · admin API + dashboard ·
audit logging · API keys · notifications. The foundation leaves seams for each
(permission guard, service layer, an events hook point) but creates no tables for
them until their slice.

## Architecture

```
Nginx (reverse proxy, TLS termination, security headers)
  └─ FastAPI (uvicorn, async)
       api/v1/*  → routes only (validation + delegation)
       services/ → business logic (auth, token, rbac)
       repositories/ → async DB access (SQLAlchemy 2.0)
       models/ → ORM entities
       core/ → config, security primitives, logging, exceptions
       middleware/ → security headers, rate limit, CSRF
       dependencies/ → get_db, get_current_user, require_permission
  ├─ PostgreSQL (users, roles, permissions, joins)
  └─ Redis (rate limiting, refresh-token blacklist, lockout counters)
```

### Auth data flow (login)

1. `POST /api/v1/auth/login` → route validates `LoginRequest`.
2. Rate-limit check (Redis, per-IP) + lockout check (per-account).
3. `AuthService.authenticate` → `UserRepository.get_by_email` → Argon2 verify.
4. On success: `TokenService` issues access + refresh JWTs (unique JTIs), sets
   httpOnly cookies + a CSRF cookie. On failure: increment lockout counter.
5. Refresh: verify refresh JWT, check JTI not blacklisted, rotate (blacklist old
   JTI, issue new pair).
6. Logout: blacklist current refresh JTI, clear cookies.

### Error handling

Central exception hierarchy (`AppError` → `AuthError`, `NotFoundError`,
`PermissionDenied`, `RateLimited`, `ValidationError`). Registered exception
handlers map them to consistent JSON `{error, detail}` with correct status codes.
Never leak internals; log the stack, return a safe message.

### Testing

- `conftest.py` builds an isolated async SQLite engine per test, overrides
  `get_db` and the Redis dependency with fakeredis.
- Factories (Factory Boy + Faker) for users/roles.
- Suites: register/login/logout/refresh/rotation/blacklist, current-user,
  RBAC permission guard (allow/deny), CSRF + rate-limit behavior.

## Later slices (build order)

1. Sessions/device tracking (needs auth) →
2. Email delivery (needs users; unblocks verification/reset) →
3. Full profile + avatar →
4. OAuth + linking →
5. 2FA →
6. Audit logging (cross-cutting; hook already present) →
7. Admin API + dashboard →
8. API keys →
9. Notifications.
