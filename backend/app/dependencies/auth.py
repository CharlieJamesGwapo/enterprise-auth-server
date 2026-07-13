"""Authentication & authorization dependencies."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request

from app.core.config import settings
from app.core.exceptions import AuthError, PermissionDenied
from app.dependencies.providers import DbSession, SessionServiceDep, TokenServiceDep
from app.models.session import Session
from app.models.user import User
from app.repositories.user import UserRepository


@dataclass
class AuthContext:
    user: User
    session: Session | None


async def get_auth_context(
    request: Request,
    session: DbSession,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
) -> AuthContext:
    """Authenticate the access token, validate its session, and track activity."""
    token = request.cookies.get(settings.ACCESS_COOKIE_NAME)
    if not token:
        raise AuthError("Not authenticated.")
    payload = tokens.verify_access(token)
    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError) as exc:
        raise AuthError("Invalid token subject.") from exc

    user = await UserRepository(session).get(user_id)
    if user is None:
        raise AuthError("User no longer exists.")
    if not user.is_active:
        raise AuthError("This account is disabled.")

    # Validate the bound session (revocation / idle / absolute expiry) and touch it.
    active_session: Session | None = None
    sid = payload.get("sid")
    if sid:
        active_session = await sessions.validate_and_touch(uuid.UUID(sid), user.id)
    return AuthContext(user=user, session=active_session)


AuthContextDep = Annotated[AuthContext, Depends(get_auth_context)]


async def get_current_user(ctx: AuthContextDep) -> User:
    return ctx.user


async def get_current_session(ctx: AuthContextDep) -> Session:
    if ctx.session is None:
        raise AuthError("No active session for this token.")
    return ctx.session


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentSession = Annotated[Session, Depends(get_current_session)]


def require_permission(code: str):
    """Return a dependency that enforces the given permission code."""

    async def _guard(user: CurrentUser) -> User:
        if not user.has_permission(code):
            raise PermissionDenied(f"Missing required permission: {code}")
        return user

    return _guard


def require_role(name: str):
    async def _guard(user: CurrentUser) -> User:
        if not user.is_superuser and name not in user.role_names:
            raise PermissionDenied(f"Requires role: {name}")
        return user

    return _guard


def verify_csrf(request: Request) -> None:
    """Double-submit CSRF check for state-changing requests."""
    cookie = request.cookies.get(settings.CSRF_COOKIE_NAME)
    header = request.headers.get(settings.CSRF_HEADER_NAME)
    if not cookie or not header or cookie != header:
        raise PermissionDenied("CSRF validation failed.")
