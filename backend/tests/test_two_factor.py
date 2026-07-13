"""Two-factor authentication tests: setup, verify, login, recovery, disable."""

from __future__ import annotations

import time

import pyotp
import pytest

pytestmark = pytest.mark.asyncio

PASSWORD = "S3curePass!word"
REG = {"email": "tfa@example.com", "password": PASSWORD, "full_name": "TFA User"}


def otp_at(secret: str, step: int = 0) -> str:
    """Return a valid TOTP code offset by ``step`` 30s windows (all within ±1)."""
    return pyotp.TOTP(secret).at(int(time.time()) + step * 30)


async def register(client) -> None:
    resp = await client.post("/api/v1/auth/register", json=REG)
    assert resp.status_code == 201, resp.text


async def enable_2fa(client) -> str:
    """Register, run setup + verify, return the TOTP secret."""
    setup = await client.post("/api/v1/auth/2fa/setup", json={"password": PASSWORD})
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    verify = await client.post("/api/v1/auth/2fa/verify", json={"otp": otp_at(secret)})
    assert verify.status_code == 200, verify.text
    assert verify.json() == {"success": True}
    return secret


# ---------------------------------------------------------------- setup/enable
async def test_status_disabled_by_default(client):
    await register(client)
    resp = await client.get("/api/v1/auth/2fa/status")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


async def test_setup_wrong_password_rejected(client):
    await register(client)
    resp = await client.post("/api/v1/auth/2fa/setup", json={"password": "wrong-pass"})
    assert resp.status_code == 401


async def test_setup_returns_qr_and_uri_but_stays_disabled(client):
    await register(client)
    resp = await client.post("/api/v1/auth/2fa/setup", json={"password": PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert body["provisioning_uri"].startswith("otpauth://totp/")
    assert "Enterprise%20Auth%20Server" in body["provisioning_uri"]
    assert body["qr_code_base64"]
    assert body["secret"]
    # Not active until verification.
    status = await client.get("/api/v1/auth/2fa/status")
    assert status.json()["enabled"] is False


async def test_qrcode_endpoint_serves_png_during_setup(client):
    await register(client)
    await client.post("/api/v1/auth/2fa/setup", json={"password": PASSWORD})
    resp = await client.get("/api/v1/auth/2fa/qrcode")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.content[:8] == b"\x89PNG\r\n\x1a\n"


async def test_verify_activates_2fa(client):
    await register(client)
    secret = await enable_2fa(client)
    assert secret
    status = await client.get("/api/v1/auth/2fa/status")
    assert status.json()["enabled"] is True


async def test_verify_invalid_otp_rejected(client):
    await register(client)
    await client.post("/api/v1/auth/2fa/setup", json={"password": PASSWORD})
    resp = await client.post("/api/v1/auth/2fa/verify", json={"otp": "000000"})
    assert resp.status_code == 401


async def test_qrcode_hidden_after_enabled(client):
    await register(client)
    await enable_2fa(client)
    resp = await client.get("/api/v1/auth/2fa/qrcode")
    assert resp.status_code == 404


# ------------------------------------------------------------------ login flow
async def test_login_requires_otp_when_2fa_enabled(client):
    await register(client)
    await enable_2fa(client)
    resp = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": PASSWORD}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["otp_required"] is True
    assert body["pre_auth_token"]
    # No session cookie issued yet.
    from app.core.config import settings

    assert settings.ACCESS_COOKIE_NAME not in resp.cookies


async def test_login_otp_completes_and_issues_session(client):
    await register(client)
    secret = await enable_2fa(client)
    challenge = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": PASSWORD}
    )
    token = challenge.json()["pre_auth_token"]
    resp = await client.post(
        "/api/v1/auth/login/otp", json={"pre_auth_token": token, "otp": otp_at(secret)}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["email"] == REG["email"]

    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200


async def test_login_otp_replay_is_rejected(client):
    await register(client)
    secret = await enable_2fa(client)
    code = otp_at(secret)

    ch1 = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": PASSWORD}
    )
    ok = await client.post(
        "/api/v1/auth/login/otp",
        json={"pre_auth_token": ch1.json()["pre_auth_token"], "otp": code},
    )
    assert ok.status_code == 200

    ch2 = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": PASSWORD}
    )
    replay = await client.post(
        "/api/v1/auth/login/otp",
        json={"pre_auth_token": ch2.json()["pre_auth_token"], "otp": code},
    )
    assert replay.status_code == 401


async def test_login_otp_bad_pre_auth_token(client):
    resp = await client.post(
        "/api/v1/auth/login/otp",
        json={"pre_auth_token": "garbage.token.value", "otp": "123456"},
    )
    assert resp.status_code == 401


# --------------------------------------------------------------- recovery codes
async def test_recovery_codes_generation(client):
    await register(client)
    secret = await enable_2fa(client)
    resp = await client.post(
        "/api/v1/auth/2fa/recovery-codes",
        json={"password": PASSWORD, "otp": otp_at(secret)},
    )
    assert resp.status_code == 201, resp.text
    codes = resp.json()["recovery_codes"]
    assert len(codes) == 10
    assert all(len(c.replace("-", "")) == 12 for c in codes)


async def test_recovery_code_login_and_one_time_use(client):
    await register(client)
    secret = await enable_2fa(client)
    gen = await client.post(
        "/api/v1/auth/2fa/recovery-codes",
        json={"password": PASSWORD, "otp": otp_at(secret)},
    )
    code = gen.json()["recovery_codes"][0]

    challenge = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": PASSWORD}
    )
    token = challenge.json()["pre_auth_token"]
    ok = await client.post(
        "/api/v1/auth/login/recovery-code",
        json={"pre_auth_token": token, "recovery_code": code},
    )
    assert ok.status_code == 200, ok.text

    # Second use of the same code must fail (one-time).
    ch2 = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": PASSWORD}
    )
    reuse = await client.post(
        "/api/v1/auth/login/recovery-code",
        json={"pre_auth_token": ch2.json()["pre_auth_token"], "recovery_code": code},
    )
    assert reuse.status_code == 401


async def test_regenerate_recovery_codes_replaces_old(client):
    await register(client)
    secret = await enable_2fa(client)
    first = await client.post(
        "/api/v1/auth/2fa/recovery-codes",
        json={"password": PASSWORD, "otp": otp_at(secret)},
    )
    old = set(first.json()["recovery_codes"])

    regen = await client.post(
        "/api/v1/auth/2fa/recovery-codes/regenerate",
        # A distinct, still-valid code (step +1 stays inside the ±1 window even
        # if the wall clock advances across a 30s boundary during the test).
        json={"password": PASSWORD, "otp": otp_at(secret, step=1)},
    )
    assert regen.status_code == 200, regen.text
    new = set(regen.json()["recovery_codes"])
    assert old.isdisjoint(new)


# ------------------------------------------------------------------- disable
async def test_disable_2fa(client):
    await register(client)
    secret = await enable_2fa(client)
    resp = await client.post(
        "/api/v1/auth/2fa/disable",
        json={"password": PASSWORD, "otp": otp_at(secret)},
    )
    assert resp.status_code == 200
    status = await client.get("/api/v1/auth/2fa/status")
    assert status.json()["enabled"] is False


async def test_disable_requires_valid_otp(client):
    await register(client)
    await enable_2fa(client)
    resp = await client.post(
        "/api/v1/auth/2fa/disable", json={"password": PASSWORD, "otp": "000000"}
    )
    assert resp.status_code == 401


async def test_disable_requires_correct_password(client):
    await register(client)
    secret = await enable_2fa(client)
    resp = await client.post(
        "/api/v1/auth/2fa/disable",
        json={"password": "wrong-pass", "otp": otp_at(secret)},
    )
    assert resp.status_code == 401


# ----------------------------------------------------------------- rate limit
async def test_2fa_endpoint_rate_limited(client):
    await register(client)
    statuses = []
    # setup is rate-limited per user at TWO_FA_RATE_LIMIT_PER_MINUTE (5).
    for _ in range(8):
        r = await client.post("/api/v1/auth/2fa/setup", json={"password": PASSWORD})
        statuses.append(r.status_code)
    assert 429 in statuses
