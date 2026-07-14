"""Email-flow tests: verification, password reset, email change, alerts."""

from __future__ import annotations

import pytest

from app.services.email.backends import OUTBOX
from tests.factories import create_user

pytestmark = pytest.mark.asyncio

PASSWORD = "S3curePass!word"
NEW_PASSWORD = "N3wStr0ng!pass"
REG = {"email": "mail@example.com", "password": PASSWORD, "full_name": "Mail User"}

CHROME = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"


def find_email(subject_part: str):
    for msg in OUTBOX:
        if subject_part.lower() in msg.subject.lower():
            return msg
    return None


def token_from(msg) -> str:
    return msg.text.split("token=")[1].strip()


async def register(client, ua: str = CHROME):
    return await client.post("/api/v1/auth/register", json=REG, headers={"user-agent": ua})


# ------------------------------------------------------------- verification
async def test_register_sends_welcome_and_verification(client):
    await register(client)
    assert find_email("Welcome") is not None
    assert find_email("Verify your email") is not None


async def test_verify_email_marks_user_verified(client):
    await register(client)
    token = token_from(find_email("Verify your email"))
    resp = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert resp.status_code == 200
    me = await client.get("/api/v1/auth/me")
    assert me.json()["is_verified"] is True


async def test_verify_email_invalid_token(client):
    await register(client)
    resp = await client.post("/api/v1/auth/verify-email", json={"token": "x" * 40})
    assert resp.status_code == 401


async def test_verify_email_token_is_single_use(client):
    await register(client)
    token = token_from(find_email("Verify your email"))
    first = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert first.status_code == 200
    second = await client.post("/api/v1/auth/verify-email", json={"token": token})
    assert second.status_code == 401


async def test_resend_verification(client):
    await register(client)
    OUTBOX.clear()
    resp = await client.post("/api/v1/auth/resend-verification")
    assert resp.status_code == 200
    assert find_email("Verify your email") is not None


# ----------------------------------------------------------- password reset
async def test_forgot_password_sends_reset_email(client):
    await register(client)
    OUTBOX.clear()
    resp = await client.post("/api/v1/auth/forgot-password", json={"email": REG["email"]})
    assert resp.status_code == 200
    assert find_email("Reset your password") is not None


async def test_forgot_password_unknown_email_is_silent(client):
    await register(client)
    OUTBOX.clear()
    resp = await client.post("/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})
    assert resp.status_code == 200
    assert find_email("Reset your password") is None  # no email leaked


async def test_reset_password_changes_credentials(client):
    await register(client)
    await client.post("/api/v1/auth/forgot-password", json={"email": REG["email"]})
    token = token_from(find_email("Reset your password"))
    OUTBOX.clear()

    resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": token, "new_password": NEW_PASSWORD},
    )
    assert resp.status_code == 200
    assert find_email("password was changed") is not None

    # New password logs in; old one is rejected.
    new_login = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": NEW_PASSWORD}
    )
    assert new_login.status_code == 200
    old_login = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": PASSWORD}
    )
    assert old_login.status_code == 401


async def test_reset_password_rejects_weak_password(client):
    await register(client)
    await client.post("/api/v1/auth/forgot-password", json={"email": REG["email"]})
    token = token_from(find_email("Reset your password"))
    resp = await client.post(
        "/api/v1/auth/reset-password", json={"token": token, "new_password": "weak"}
    )
    assert resp.status_code == 422


# ------------------------------------------------------------- email change
async def test_change_email_flow(client):
    await register(client)
    OUTBOX.clear()
    req = await client.post(
        "/api/v1/auth/change-email",
        json={"new_email": "changed@example.com", "password": PASSWORD},
    )
    assert req.status_code == 200
    msg = find_email("Confirm your new email")
    assert msg is not None and msg.to == "changed@example.com"

    confirm = await client.post(
        "/api/v1/auth/confirm-email-change", json={"token": token_from(msg)}
    )
    assert confirm.status_code == 200
    me = await client.get("/api/v1/auth/me")
    assert me.json()["email"] == "changed@example.com"


async def test_change_email_wrong_password(client):
    await register(client)
    resp = await client.post(
        "/api/v1/auth/change-email",
        json={"new_email": "x@example.com", "password": "wrong-pass"},
    )
    assert resp.status_code == 401


async def test_change_email_to_existing_address_conflicts(client, seeded_session):
    await create_user(seeded_session, email="taken@example.com")
    await register(client)
    resp = await client.post(
        "/api/v1/auth/change-email",
        json={"new_email": "taken@example.com", "password": PASSWORD},
    )
    assert resp.status_code == 409


# ------------------------------------------------------------ registration policy
async def test_register_rejects_weak_password(client):
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "weak@example.com", "password": "weak", "full_name": "W"},
    )
    assert resp.status_code == 422


# -------------------------------------------------------------- device alerts
async def test_new_device_login_sends_alert(client):
    await register(client, ua=CHROME)
    OUTBOX.clear()
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": PASSWORD},
        headers={"user-agent": FIREFOX},
    )
    assert login.status_code == 200
    assert find_email("New sign-in") is not None


async def test_same_device_login_no_alert(client):
    await register(client, ua=CHROME)
    OUTBOX.clear()
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": REG["email"], "password": PASSWORD},
        headers={"user-agent": CHROME},
    )
    assert login.status_code == 200
    assert find_email("New sign-in") is None
