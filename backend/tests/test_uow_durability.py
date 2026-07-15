"""Regression: state-mutating-then-erroring ops must persist to the DB, not just Redis."""

from __future__ import annotations

import uuid as uuidlib

import pytest
from sqlalchemy import select

from app.core import config
from app.models.session import Session

pytestmark = pytest.mark.asyncio
PASSWORD = "S3curePass!word"
REG = {"email": "uow@example.com", "password": PASSWORD, "full_name": "U"}


async def test_idle_expiry_marks_session_inactive_in_db(client, session_factory, monkeypatch):
    await client.post("/api/v1/auth/register", json=REG)
    sid = (await client.get("/api/v1/sessions")).json()[0]["session_id"]

    monkeypatch.setattr(config.settings, "SESSION_IDLE_TIMEOUT_MINUTES", 0)
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401  # rejected (via redis)

    async with session_factory() as s:
        row = (
            await s.execute(select(Session).where(Session.session_uuid == uuidlib.UUID(sid)))
        ).scalar_one()
    assert row.is_active is False, (
        "DB row still active after idle expiry — UoW rolled back the mutation"
    )


async def test_refresh_replay_persists_revocation_in_db(client, session_factory):
    await client.post("/api/v1/auth/register", json=REG)
    sid = (await client.get("/api/v1/sessions")).json()[0]["session_id"]
    old = client.cookies.get("refresh_token")
    await client.post("/api/v1/auth/refresh")  # rotate
    from app.core.config import settings

    client.cookies.set("refresh_token", old, path=f"{settings.API_V1_PREFIX}/auth")
    replay = await client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401

    async with session_factory() as s:
        row = (
            await s.execute(select(Session).where(Session.session_uuid == uuidlib.UUID(sid)))
        ).scalar_one()
    assert row.is_active is False, (
        "DB row still active after refresh-replay revocation — UoW rolled it back"
    )
