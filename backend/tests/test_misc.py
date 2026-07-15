"""Health, readiness, current-user, logging, and refresh-edge coverage."""

from __future__ import annotations

import logging

from app.core.config import settings
from app.core.logging import JsonFormatter, configure_logging

REG = {"email": "dan@example.com", "password": "S3curePass!word", "full_name": "Dan"}


async def test_health_endpoint(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json() == {"detail": "ok"}


async def test_ready_endpoint_checks_db_and_redis(client):
    resp = await client.get("/api/v1/ready")
    assert resp.status_code == 200
    assert resp.json()["detail"] == "ready"


async def test_users_me_returns_profile(client):
    await client.post("/api/v1/auth/register", json=REG)
    resp = await client.get("/api/v1/users/me")
    assert resp.status_code == 200
    assert resp.json()["email"] == REG["email"]


async def test_refresh_without_cookie_rejected(client):
    resp = await client.post("/api/v1/auth/refresh")
    assert resp.status_code == 401
    assert resp.json()["error"] == "authentication_error"


async def test_me_with_tampered_token_rejected(client):
    await client.post("/api/v1/auth/register", json=REG)
    client.cookies.set(settings.ACCESS_COOKIE_NAME, "not-a-real-jwt", path="/")
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


async def test_validation_error_uses_unified_envelope(client):
    resp = await client.post(
        "/api/v1/auth/register",
        json={"email": "notanemail", "password": "S3curePass!word", "full_name": "Bad Email"},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"] == "validation_error"
    assert body["detail"] == "Request validation failed."
    assert isinstance(body["context"], list)
    assert len(body["context"]) > 0


async def test_unknown_route_uses_unified_envelope(client):
    resp = await client.get("/api/v1/does-not-exist")
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"] == "http_error"
    assert "detail" in body


def test_json_formatter_emits_structured_fields():
    configure_logging("INFO")
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    record.user_id = "abc-123"
    import json

    payload = json.loads(formatter.format(record))
    assert payload["message"] == "hello"
    assert payload["level"] == "INFO"
    assert payload["user_id"] == "abc-123"
