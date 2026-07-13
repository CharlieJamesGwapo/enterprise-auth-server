"""Authentication & authorization dependencies."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, Request

from app.core.config import settings
from app.core.exceptions import AuthError, PermissionDenied
from app.dependencies.providers import DbSession, TokenServiceDep
from app.models.user import User
from app.repositories.user import UserRepository


async def get_current_user(
    request: Request,
    session: DbSession,
    tokens: TokenServiceDep,
) -> User:
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
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


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
