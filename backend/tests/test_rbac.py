"""RBAC tests: permission guard allows/denies correctly."""

from __future__ import annotations

import pytest

from tests.factories import DEFAULT_PASSWORD, create_user

pytestmark = pytest.mark.asyncio


async def _login(client, email: str) -> None:
    resp = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": DEFAULT_PASSWORD}
    )
    assert resp.status_code == 200, resp.text


async def test_admin_can_list_users(client, seeded_session):
    admin = await create_user(seeded_session, role="admin", email="admin@example.com")
    await _login(client, admin.email)
    resp = await client.get("/api/v1/users")
    assert resp.status_code == 200
    assert isinstance(resp.json()["items"], list)


async def test_plain_user_cannot_list_users(client, seeded_session):
    user = await create_user(seeded_session, role="user", email="bob@example.com")
    await _login(client, user.email)
    resp = await client.get("/api/v1/users")
    assert resp.status_code == 403
    assert resp.json()["error"] == "permission_denied"


async def test_superuser_bypasses_permission_checks(client, seeded_session):
    su = await create_user(seeded_session, role="user", email="root@example.com", is_superuser=True)
    await _login(client, su.email)
    resp = await client.get("/api/v1/users")
    assert resp.status_code == 200


async def test_permission_codes_map_to_roles(seeded_session):
    admin = await create_user(seeded_session, role="admin", email="a2@example.com")
    assert "manage_users" in admin.permission_codes
    assert "view_dashboard" in admin.permission_codes

    plain = await create_user(seeded_session, role="user", email="u2@example.com")
    assert plain.permission_codes == set()
