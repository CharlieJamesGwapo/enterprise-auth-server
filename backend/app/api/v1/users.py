"""User routes. Includes an RBAC-protected example endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.dependencies.auth import CurrentSession, CurrentUser, require_permission
from app.dependencies.providers import DbSession, SessionServiceDep
from app.repositories.user import UserRepository
from app.schemas.common import Page
from app.schemas.session import LastLoginRead
from app.schemas.user import UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserRead)
async def read_me(user: CurrentUser) -> UserRead:
    return UserRead.from_model(user)


@router.get("/last-login", response_model=LastLoginRead)
async def last_login(
    user: CurrentUser, current: CurrentSession, sessions: SessionServiceDep
) -> LastLoginRead:
    """Return details of the previous login (before the current session)."""
    prev = await sessions.previous_login(user, current)
    if prev is None:
        return LastLoginRead()
    return LastLoginRead(
        previous_login_at=prev.login_at,
        previous_login_ip=prev.ip_address,
        previous_device=prev.device_name,
        previous_browser=prev.browser,
    )


@router.get(
    "",
    response_model=Page[UserRead],
    dependencies=[Depends(require_permission("manage_users"))],
)
async def list_users(
    session: DbSession,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[UserRead]:
    repo = UserRepository(session)
    users = await repo.list_all(limit=limit, offset=offset)
    total = await repo.count_all()
    return Page(
        items=[UserRead.from_model(u) for u in users],
        total=total,
        limit=limit,
        offset=offset,
    )
