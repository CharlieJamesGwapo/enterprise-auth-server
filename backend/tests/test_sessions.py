"""Session management tests: creation, listing, revocation, expiry, device detection."""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.useragent import parse_user_agent

pytestmark = pytest.mark.asyncio

PASSWORD = "S3curePass!word"
REG = {"email": "sess@example.com", "password": PASSWORD, "full_name": "Sess User"}

CHROME_MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
FIREFOX_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
IPHONE_SAFARI = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
)


async def register(client, ua: str = CHROME_MAC) -> None:
    resp = await client.post("/api/v1/auth/register", json=REG, headers={"user-agent": ua})
    assert resp.status_code == 201, resp.text


# ---------------------------------------------------------------- device detection
def test_device_detection_desktop_chrome():
    info = parse_user_agent(CHROME_MAC)
    assert info.browser == "Chrome"
    assert info.browser_version.startswith("120")
    assert info.operating_system == "Mac OS X"
    assert info.device_type == "Desktop"


def test_device_detection_mobile_safari():
    info = parse_user_agent(IPHONE_SAFARI)
    assert info.browser in {"Mobile Safari", "Safari"}
    assert info.operating_system == "iOS"
    assert info.device_type == "Mobile"


def test_device_detection_handles_empty_ua():
    info = parse_user_agent("")
    assert info.device_type == "Unknown"
    assert info.browser == "Unknown"


# ----------------------------------------------------------------- session creation
async def test_login_creates_session(client):
    await register(client)
    resp = await client.get("/api/v1/sessions")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    s = body[0]
    assert s["browser"] == "Chrome"
    assert s["os"] == "Mac OS X"
    assert s["current"] is True
    assert s["status"] == "active"


async def test_each_login_creates_independent_session(client):
    await register(client)
    # A second login from a different device creates a second session.
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": PASSWORD},
        headers={"user-agent": FIREFOX_WIN},
    )
    assert login.status_code == 200
    resp = await client.get("/api/v1/sessions")
    assert len(resp.json()) == 2
    browsers = {s["browser"] for s in resp.json()}
    assert browsers == {"Chrome", "Firefox"}


async def test_get_single_session_and_ownership(client):
    await register(client)
    listed = await client.get("/api/v1/sessions")
    sid = listed.json()[0]["session_id"]
    resp = await client.get(f"/api/v1/sessions/{sid}")
    assert resp.status_code == 200
    assert resp.json()["session_id"] == sid
    # A random, non-owned id is 404.
    missing = await client.get("/api/v1/sessions/00000000-0000-0000-0000-000000000000")
    assert missing.status_code == 404


# --------------------------------------------------------------------- revocation
async def test_logout_current_session_revokes_access(client):
    await register(client)
    resp = await client.post("/api/v1/sessions/logout")
    assert resp.status_code == 200
    assert resp.json()["revoked_sessions"] == 1
    # The access token is now bound to a revoked session → further calls fail.
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 401


async def test_delete_specific_session(client):
    await register(client)
    # Create a second session to delete.
    await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": PASSWORD},
        headers={"user-agent": FIREFOX_WIN},
    )
    sessions = (await client.get("/api/v1/sessions")).json()
    other = next(s for s in sessions if not s["current"])
    resp = await client.delete(f"/api/v1/sessions/{other['session_id']}")
    assert resp.status_code == 200
    remaining = (await client.get("/api/v1/sessions")).json()
    assert len(remaining) == 1
    assert remaining[0]["current"] is True


async def test_delete_session_with_mismatched_csrf_forbidden(client):
    await register(client)
    sessions = (await client.get("/api/v1/sessions")).json()
    sid = sessions[0]["session_id"]
    resp = await client.delete(
        f"/api/v1/sessions/{sid}", headers={settings.CSRF_HEADER_NAME: "wrong-token"}
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "permission_denied"
    # Session was not revoked.
    remaining = (await client.get("/api/v1/sessions")).json()
    assert len(remaining) == 1


async def test_logout_all_devices(client):
    await register(client)
    await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": PASSWORD},
        headers={"user-agent": FIREFOX_WIN},
    )
    resp = await client.post("/api/v1/sessions/logout-all")
    assert resp.status_code == 200
    assert resp.json()["revoked_sessions"] == 2
    # Current session is revoked too → subsequent requests are unauthenticated.
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 401


# --------------------------------------------------------------------- last login
async def test_last_login_returns_previous_session(client):
    await register(client)  # session 1
    await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": PASSWORD},
        headers={"user-agent": FIREFOX_WIN},
    )  # session 2 becomes current
    resp = await client.get("/api/v1/users/last-login")
    assert resp.status_code == 200
    body = resp.json()
    # Previous login is session 1 (Chrome/macOS).
    assert body["previous_browser"] == "Chrome"
    assert body["previous_login_at"] is not None


async def test_last_login_none_for_single_session(client):
    await register(client)
    resp = await client.get("/api/v1/users/last-login")
    assert resp.status_code == 200
    assert resp.json()["previous_login_at"] is None


# --------------------------------------------------------------------- expiry
async def test_expired_session_is_rejected(client, monkeypatch):
    await register(client)
    # Force the idle timeout to zero so the next request is treated as expired.
    from app.core import config

    monkeypatch.setattr(config.settings, "SESSION_IDLE_TIMEOUT_MINUTES", 0)
    # Also clear the activity throttle so validation actually re-evaluates.
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


async def test_refresh_keeps_session_and_rotates(client):
    await register(client)
    before = (await client.get("/api/v1/sessions")).json()[0]["session_id"]
    r = await client.post("/api/v1/auth/refresh")
    assert r.status_code == 200
    after = (await client.get("/api/v1/sessions")).json()
    # Same session id survives rotation.
    assert len(after) == 1
    assert after[0]["session_id"] == before
