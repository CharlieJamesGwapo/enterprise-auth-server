"""Session management routes: list, inspect, and revoke sessions."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.core.cookies import clear_auth_cookies
from app.dependencies.auth import CurrentSession, CurrentUser
from app.dependencies.providers import SessionServiceDep
from app.models.session import Session
from app.schemas.session import LogoutResponse, SessionRead

router = APIRouter(prefix="/sessions", tags=["sessions"])


def _to_read(record: Session, current_uuid: uuid.UUID) -> SessionRead:
    return SessionRead(
        session_id=record.session_uuid,
        device=record.device_name,
        device_type=record.device_type,
        browser=record.browser,
        browser_version=record.browser_version,
        os=record.operating_system,
        os_version=record.operating_system_version,
        ip=record.ip_address,
        country=record.country,
        city=record.city,
        login_at=record.login_at,
        last_activity=record.last_activity_at,
        current=record.session_uuid == current_uuid,
        status="active" if record.is_active else "inactive",
    )


@router.get("", response_model=list[SessionRead])
async def list_sessions(
    user: CurrentUser, current: CurrentSession, sessions: SessionServiceDep
) -> list[SessionRead]:
    """List all active sessions for the current user."""
    records = await sessions.list_active(user)
    return [_to_read(r, current.session_uuid) for r in records]


@router.get("/{session_id}", response_model=SessionRead)
async def get_session(
    session_id: uuid.UUID,
    user: CurrentUser,
    current: CurrentSession,
    sessions: SessionServiceDep,
) -> SessionRead:
    """Fetch a single session owned by the current user."""
    record = await sessions.get_owned(user, session_id)
    return _to_read(record, current.session_uuid)


@router.post("/logout", response_model=LogoutResponse)
async def logout_current(
    response: Response,
    user: CurrentUser,
    current: CurrentSession,
    sessions: SessionServiceDep,
) -> LogoutResponse:
    """Revoke the current session and clear auth cookies."""
    await sessions.revoke(current, reason="logout")
    await sessions.session.commit()
    clear_auth_cookies(response)
    return LogoutResponse(detail="Current session logged out.", revoked_sessions=1)


@router.post("/logout-all", response_model=LogoutResponse)
async def logout_all(
    response: Response,
    user: CurrentUser,
    current: CurrentSession,
    sessions: SessionServiceDep,
) -> LogoutResponse:
    """Revoke every active session for the user (including this one)."""
    count = await sessions.revoke_all(user, reason="logout_all")
    await sessions.session.commit()
    clear_auth_cookies(response)
    return LogoutResponse(detail="Logged out from all devices.", revoked_sessions=count)


@router.delete("/{session_id}", response_model=LogoutResponse)
async def revoke_session(
    session_id: uuid.UUID,
    user: CurrentUser,
    current: CurrentSession,
    sessions: SessionServiceDep,
) -> LogoutResponse:
    """Revoke a specific session by id (ownership enforced)."""
    await sessions.revoke_by_uuid(user, session_id, reason="revoked_by_user")
    await sessions.session.commit()
    return LogoutResponse(detail="Session revoked.", revoked_sessions=1)
