"""Auth flow tests: register, login, refresh rotation, logout, current user."""

from __future__ import annotations

import pytest

from app.core.config import settings

pytestmark = pytest.mark.asyncio

REG = {"email": "alice@example.com", "password": "S3curePass!word", "full_name": "Alice"}


async def test_register_creates_user_and_sets_cookies(client):
    resp = await client.post("/api/v1/auth/register", json=REG)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["user"]["email"] == "alice@example.com"
    assert body["user"]["roles"] == ["user"]
    assert body["csrf_token"]
    assert settings.ACCESS_COOKIE_NAME in resp.cookies
    assert settings.REFRESH_COOKIE_NAME in resp.cookies


async def test_register_duplicate_email_conflicts(client):
    await client.post("/api/v1/auth/register", json=REG)
    resp = await client.post("/api/v1/auth/register", json=REG)
    assert resp.status_code == 409
    assert resp.json()["error"] == "conflict"


async def test_login_success_and_me(client):
    await client.post("/api/v1/auth/register", json=REG)
    login = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": REG["password"]}
    )
    assert login.status_code == 200, login.text

    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == REG["email"]


async def test_login_wrong_password_rejected(client):
    await client.post("/api/v1/auth/register", json=REG)
    resp = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": "wrong-password"}
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "authentication_error"


async def test_me_requires_authentication(client):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


async def test_refresh_rotates_and_old_token_is_revoked(client):
    await client.post("/api/v1/auth/register", json=REG)
    await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": REG["password"]}
    )
    old_refresh = client.cookies.get(settings.REFRESH_COOKIE_NAME)

    first = await client.post("/api/v1/auth/refresh")
    assert first.status_code == 200
    new_refresh = client.cookies.get(settings.REFRESH_COOKIE_NAME)
    assert new_refresh != old_refresh

    # Re-using the OLD refresh token must fail (rotation + blacklist).
    client.cookies.set(
        settings.REFRESH_COOKIE_NAME, old_refresh, path=f"{settings.API_V1_PREFIX}/auth"
    )
    replay = await client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401


async def test_refresh_replay_revokes_whole_session_family(client):
    """Replaying an already-rotated refresh token must kill the whole session,
    not just reject the stale token — a stolen refresh token should not let an
    attacker (or the legit user) keep using the session afterwards.
    """
    await client.post("/api/v1/auth/register", json=REG)
    await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": REG["password"]}
    )
    old_refresh = client.cookies.get(settings.REFRESH_COOKIE_NAME)

    first = await client.post("/api/v1/auth/refresh")
    assert first.status_code == 200
    new_refresh = client.cookies.get(settings.REFRESH_COOKIE_NAME)

    # Replay the OLD (already-rotated) refresh token -> 401, and the session
    # family is revoked as a side effect.
    client.cookies.set(
        settings.REFRESH_COOKIE_NAME, old_refresh, path=f"{settings.API_V1_PREFIX}/auth"
    )
    replay = await client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401

    # The NEW (legitimate, rotated) refresh token must now also be rejected —
    # the whole session was revoked, not just the replayed token.
    client.cookies.set(
        settings.REFRESH_COOKIE_NAME, new_refresh, path=f"{settings.API_V1_PREFIX}/auth"
    )
    legit_refresh = await client.post("/api/v1/auth/refresh")
    assert legit_refresh.status_code == 401

    # The current access cookie is also dead now (session revoked).
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 401


async def test_logout_clears_cookies_and_blocks_me(client):
    reg = await client.post("/api/v1/auth/register", json=REG)
    csrf = reg.json()["csrf_token"]
    resp = await client.post("/api/v1/auth/logout", headers={settings.CSRF_HEADER_NAME: csrf})
    assert resp.status_code == 200
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 401


async def test_logout_without_csrf_forbidden(client):
    await client.post("/api/v1/auth/register", json=REG)
    resp = await client.post(
        "/api/v1/auth/logout", headers={settings.CSRF_HEADER_NAME: "wrong-token"}
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "permission_denied"


async def test_logout_then_refresh_is_rejected(client):
    """After logout, replaying the pre-logout refresh token must fail (session revoked)."""
    reg = await client.post("/api/v1/auth/register", json=REG)
    assert reg.status_code == 201
    refresh = client.cookies.get(settings.REFRESH_COOKIE_NAME)

    out = await client.post("/api/v1/auth/logout")  # CSRF header auto-injected by fixture
    assert out.status_code == 200

    # Re-present the captured refresh token: the session was revoked at logout.
    client.cookies.set(settings.REFRESH_COOKIE_NAME, refresh, path=f"{settings.API_V1_PREFIX}/auth")
    resp = await client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401
