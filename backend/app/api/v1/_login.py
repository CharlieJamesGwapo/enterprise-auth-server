"""Shared login-finalization helper.

Not a router module — used by both ``auth.py`` and ``oauth.py`` to issue a
session after credentials (password, 2FA, or OAuth) have been verified. Lives
outside both routers to avoid a route-to-route import.
"""

from __future__ import annotations

import uuid

from fastapi import BackgroundTasks, Request, Response

from app.core.cookies import set_auth_cookies
from app.core.security import generate_csrf_token
from app.dependencies.providers import (
    NotificationServiceDep,
    SessionServiceDep,
    TokenServiceDep,
)
from app.middleware.rate_limit import client_ip
from app.schemas.auth import AuthResponse
from app.schemas.user import UserRead


async def _finalize_login(
    request: Request,
    response: Response,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
    notifications: NotificationServiceDep,
    background: BackgroundTasks,
    user,
    remember_me: bool,
) -> AuthResponse:
    """Issue a session: mint tokens bound to a new session id and persist it."""
    session_uuid = uuid.uuid4()
    pair, refresh_jti = tokens.issue_pair(
        str(user.id), remember_me=remember_me, session_id=str(session_uuid)
    )
    record, is_new_device = await sessions.create_session(
        user=user,
        session_uuid=session_uuid,
        refresh_jti=refresh_jti,
        remember_me=remember_me,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        headers=dict(request.headers),
    )
    if is_new_device:
        background.add_task(
            notifications.send_new_device_alert,
            user.email,
            device=record.device_name,
            browser=record.browser,
            ip=record.ip_address,
        )
    csrf = generate_csrf_token()
    set_auth_cookies(response, pair, csrf)
    return AuthResponse(user=UserRead.from_model(user), csrf_token=csrf)
