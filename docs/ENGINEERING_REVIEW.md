# Engineering Review Report — Enterprise Authentication Server

*Principal review synthesizing 8 specialized review audits (Architecture, Security,
Database, API, Performance, Testing, Developer Experience, Enterprise Feature Gaps).*
*Codebase: FastAPI 3.12 auth server · 81 tests / 93% coverage · slices: auth, 2FA,
sessions, email, OAuth.*
*Date: 2026-07-15.*

---

## Scorecard

| Dimension | Score | Verdict |
|---|---|---|
| Overall Architecture | 71 | Clean layering + typed DI, undermined by undefined transaction ownership |
| Security | 48 | Excellent primitives; two directly-exploitable Criticals |
| API Design | 54 | Half-finished error/response standardization; no pagination |
| Database | 72 | Strong FK/constraint/tz hygiene; missing composite indexes + pool tuning |
| Performance | 58 | Sync argon2 blocks the loop; uncached 4-SELECT auth path |
| Maintainability | 65 | Readable/consistent, but tribal-knowledge commit rules |
| Testing | 68 | Broad, but mocks away the riskiest code |
| **Production Readiness** | **55** | **Blocked** until the 2 Criticals + fail-open limiter are fixed |

Meta-theme: the happy path is well-engineered; the failure modes and trust
boundaries are not. Every Critical/High is a misconfiguration, partial failure, or
unverified-trust issue — not a broken feature.

---

## Identified Weaknesses

### CRITICAL — block production

- **C1 · OAuth account takeover by unverified email** — `services/oauth/service.py:133`.
  Callback auto-links to any local account matching the provider email without
  checking `email_verified`. Attacker sets a provider email to `victim@corp.com` →
  "Sign in with GitHub" → lands in victim's account, bypassing password and 2FA.
  Fix: require `email_verified == true` AND local email verified before auto-link;
  otherwise force an authenticated explicit-link step. Complexity S.
- **C2 · Hardcoded production-capable secrets** — `core/config.py:22-24,34`.
  `SECRET_KEY` and a valid Fernet `ENCRYPTION_KEY` have working in-source defaults; no
  validator rejects them in prod. Omit the env var → forgeable JWTs + decryptable TOTP
  secrets. Fix: `model_validator` fails startup if `is_production` and value == default.
  Complexity S.

### HIGH

- **H1 · Rate limiter/lockout fails open on Redis error** — `middleware/rate_limit.py:30`,
  `services/rate_limit.py`. Redis blip removes all brute-force protection. Fix: fail
  closed for `/auth/*` + 2FA; fail open elsewhere.
- **H2 · CSRF wired to one route** — `dependencies/auth.py:92`. `verify_csrf` guards only
  `POST /logout`; `logout-all`, `DELETE /sessions/{id}`, and 2FA routes rely on
  `SameSite=Lax` alone. Fix: apply to all cookie-auth mutations; use
  `secrets.compare_digest`.
- **H3 · Undefined transaction / unit-of-work ownership** — `api/v1/auth.py:79,125`;
  `services/session.py:148`; 2FA routes commit via `service.session.commit()`. Some
  services self-commit, others expect the route to. Risk: partial writes. Fix: one
  explicit commit point per request.
- **H4 · Argon2 + QR/PIL run synchronously in `async def`** — `services/two_factor.py:167`,
  `services/auth.py:35,50`. Blocks the event loop; recovery login loops ≤10 sequential
  argon2 verifies. Fix: `anyio.to_thread.run_sync`; set explicit Argon2 cost params.
- **H5 · Uncached roles+permissions cascade every request** — `models/user.py:24`,
  `dependencies/auth.py:41`. `lazy="selectin"` + separate session query = ≥4 serial
  SELECTs per authed request, uncached. Fix: short-TTL permission cache; parallelize
  user+session load.
- **H6 · Error envelope diverges from FastAPI validation errors** — `core/exceptions.py:67`.
  `AppError` → `{error,detail,context}`; Pydantic 422 → `{"detail":[...]}`. Fix:
  `RequestValidationError` handler mapping into the unified envelope.
- **H7 · No pagination/filtering on list endpoints** — `api/v1/users.py:43`,
  `sessions.py:37`. Unbounded `SELECT *`. `users.py` also bypasses the repository.
- **H8 · Missing composite indexes for hot queries** — `models/session.py`,
  `repositories/session.py:22`. `WHERE user_id AND is_active ORDER BY last_activity_at`
  has only single-column indexes. Also `email_tokens(user_id,purpose)`.
- **H9 · Real OAuth provider HTTP code 100% untested** — `services/oauth/providers.py`
  (40% cov). All tests use `FakeProvider`. Fix: `respx`/`pytest-httpx` transport tests.

### MEDIUM

Untuned connection pool (15-conn ceiling, no `pool_recycle`); per-email lockout is a
victim-targeted DoS (add IP+email / CAPTCHA); refresh-token family revocation missing on
replay-race; registration enumerates accounts via 409; random UUIDv4 PKs cause B-tree
bloat (→ UUIDv7/ULID); unbounded `list_for_user(active_only=False)` at login; unpipelined
Redis (2–4 RTTs/request); no request-ID/correlation in logs; audit is log-only (no DB);
weak password policy (8-char, tiny denylist, no HIBP); no unified success envelope;
verb-in-path + duplicate session-revoke paths.

### LOW

OpenAPI docs exposed in prod; `SessionService` builds its own `TokenService` in DI; lazy
password import with no real cycle; `services/oauth/` subpackage inconsistency; sync tests
carry module-level `pytest.mark.asyncio`; TOTP time-boundary test flakiness; no
mypy/pip-audit/pre-commit; CI has no dep cache; MailHog documented but not in Compose;
Compose `api`/`nginx` lack healthchecks.

> Corrections to raw agent findings: TOTP **replay protection is already implemented**
> (`verify_totp` marks the used code in Redis; a passing test exists). Blacklist check
> **propagates** on Redis error rather than silently honoring tokens.

---

## Enterprise Feature Gaps (by value tier)

- **Tier 1:** Audit-log persistence + query/export (S) · Organizations/Workspaces +
  membership roles (L) · Invitations (S) · API Keys / M2M (M) · Asymmetric JWT
  (RS256/EdDSA) + JWKS + key rotation (M).
- **Tier 2:** Passkeys/WebAuthn (M) · SSO SAML/OIDC-provider (L) · SCIM (L) ·
  Webhooks/outbox (M) · Admin/security dashboard (M) · Risk/anomaly detection + real
  GeoIP (M) · Step-up auth (S) · Magic links (S) · HIBP breach check (S).
- **Tier 3:** Device-trust/remember-device (S) · OpenTelemetry+Prometheus (M) · GDPR
  export/delete (M) · CAPTCHA (S) · Feature flags (M) · Rate-limit admin API (S).

---

## Prioritized Improvement Backlog

| # | Item | Priority | Cx | Depends on | Risk if unfixed |
|---|---|---|---|---|---|
| 1 | C1 OAuth email-verify link | P0 | S | — | Account takeover |
| 2 | C2 Secret prod-validator | P0 | S | — | Full impersonation on misconfig |
| 3 | H1 Fail-closed limiter (auth) | P0 | M | — | Brute-force during outage |
| 4 | H2 CSRF on all mutations | P1 | S | — | Forced session revocation |
| 5 | H3 Unit-of-work commit point | P1 | M | all services | Partial writes |
| 6 | H4 Threadpool hashing + Argon2 params | P1 | M | — | Loop stalls under load |
| 7 | H5 Permission cache + join auth path | P1 | M | Redis | DB load × request volume |
| 8 | H8 Composite indexes + pool tuning | P1 | S | — | Slow sessions, conn exhaustion |
| 9 | H6 Unified error envelope | P1 | S | — | Client fragility |
| 10 | H7 Pagination/filtering | P1 | M | envelope | Latency/DoS at scale |
| 11 | H9 Real-provider OAuth tests | P1 | M | respx | Untested external integration |
| 12 | Refresh-family revocation | P2 | M | schema | Token-theft race |
| 13 | Request-ID + audit-DB persistence | P2 | S+L | — | Un-investigable incidents |

---

## Sonnet 5 Execution Plan (13 milestones — security first)

Each milestone is independently executable, backward-compatible, and gated by
`make check` (lint + 95%-target tests). The reviewer reviews each before merge.

1. **M1 · Security Criticals & Hardening** — C1, C2, H2, constant-time CSRF, gate `/docs`
   in prod. Risk: OAuth link-UX change (acceptable).
2. **M2 · Fail-Safe Defaults** — H1 fail-closed limiter for auth routes, refresh-family
   revocation, IP+email lockout scoping. Dep: M1.
3. **M3 · Architecture Cleanup** — H3 single commit point/UoW; extract `_finalize_login`
   → `SessionService.issue_session`; `AuthServiceDep`; route `users.py` through repo; drop
   lazy imports.
4. **M4 · Database Optimization** — H8 composite indexes, pool config, UUIDv7 default,
   `(user_id,purpose)` index. Additive migration.
5. **M5 · API Standardization** — H6 validation-error handler, unified success envelope
   (additive), H7 pagination + filters, status-code policy, OpenAPI error docs. Dep: M3.
6. **M6 · Performance** — H4 threadpool hashing + Argon2 params, H5 permission cache +
   parallel loads, Redis pipelining, bounded new-device query. Dep: M3/M4.
7. **M7 · Testing to 95%+** — respx provider tests, absolute-expiry, per-rule password,
   refresh-after-revoke, lockout boundary + TTL reset, fail-open test, split sync tests.
8. **M8 · DX & Observability** — request-ID middleware + log correlation, Compose
   healthchecks, mypy + pip-audit + pre-commit, CI dep cache, MailHog profile.
9. **M9 · Audit-Log Persistence** — `audit_logs` table + query/export API.
10. **M10 · Passkeys + Magic Links + Step-up** — WebAuthn into the 2FA module; passwordless
    via email-token infra; re-auth for sensitive ops.
11. **M11 · API Keys (M2M)** — hashed-at-rest keys + scopes.
12. **M12 · Organizations + Invitations + Asymmetric JWT/JWKS** — org-scoped RBAC,
    membership roles, invitations, RS256/EdDSA + JWKS + key rotation.
13. **M13 · Webhooks + Risk Detection + Observability + Final Refactor** — outbox off
    persisted audit, impossible-travel/new-IP scoring, OpenTelemetry/Prometheus.

**Bottom line:** strong engineering artifact, but not a shippable production auth platform
until M1–M2 (the OAuth auto-link and hardcoded-secret Criticals are directly exploitable to
full account takeover). After M1–M8 it is a solid production auth server; M9–M13 make it an
enterprise platform.
