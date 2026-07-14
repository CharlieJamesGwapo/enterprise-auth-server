"""Security tests: brute-force lockout, rate limiting, security headers, hashing."""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.security import hash_password, needs_rehash, verify_password

pytestmark = pytest.mark.asyncio

REG = {"email": "carol@example.com", "password": "S3curePass!word", "full_name": "Carol"}


def test_argon2_hashing_roundtrip():
    hashed = hash_password("hunter2-long-password")
    assert hashed != "hunter2-long-password"
    assert hashed.startswith("$argon2")
    assert verify_password("hunter2-long-password", hashed)
    assert not verify_password("wrong", hashed)
    assert not needs_rehash(hashed)


async def test_account_locks_after_repeated_failures(client):
    await client.post("/api/v1/auth/register", json=REG)
    # Exhaust the failure budget.
    for _ in range(settings.MAX_FAILED_LOGINS):
        r = await client.post(
            "/api/v1/auth/login", json={"email": REG["email"], "password": "nope"}
        )
        assert r.status_code == 401

    # Even the CORRECT password is now refused while locked out.
    locked = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": REG["password"]}
    )
    assert locked.status_code == 401
    assert locked.json()["error"] == "account_locked"


async def test_lockout_is_scoped_per_ip_not_just_email(client):
    """An attacker who only knows a victim's email must not be able to lock
    the victim out from a different IP — lockout keys on (email, IP).
    """
    await client.post("/api/v1/auth/register", json=REG)

    # Attacker on IP A exhausts the failure budget for the victim's email.
    attacker_headers = {"X-Forwarded-For": "10.0.0.1"}
    for _ in range(settings.MAX_FAILED_LOGINS):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": REG["email"], "password": "nope"},
            headers=attacker_headers,
        )
        assert r.status_code == 401

    # IP A is now locked out for this email, even with the correct password.
    locked = await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": REG["password"]},
        headers=attacker_headers,
    )
    assert locked.status_code == 401
    assert locked.json()["error"] == "account_locked"

    # The victim, logging in from a different IP, is unaffected.
    victim_headers = {"X-Forwarded-For": "10.0.0.2"}
    victim_login = await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": REG["password"]},
        headers=victim_headers,
    )
    assert victim_login.status_code == 200, victim_login.text


async def test_security_headers_present(client):
    resp = await client.get("/api/v1/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers


async def test_auth_rate_limit_enforced(client):
    # Auth endpoints are limited per IP; exceed the window.
    limit = settings.AUTH_RATE_LIMIT_PER_MINUTE
    statuses = []
    for _ in range(limit + 3):
        r = await client.post(
            "/api/v1/auth/login", json={"email": "x@example.com", "password": "whatever1"}
        )
        statuses.append(r.status_code)
    assert 429 in statuses
