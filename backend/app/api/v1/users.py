"""User routes. Includes an RBAC-protected example endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.dependencies.auth import CurrentUser, require_permission
from app.dependencies.providers import DbSession
from app.models.user import User
from app.schemas.user import UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserRead)
async def read_me(user: CurrentUser) -> UserRead:
    return UserRead.from_model(user)


@router.get(
    "",
    response_model=list[UserRead],
    dependencies=[Depends(require_permission("manage_users"))],
)
async def list_users(session: DbSession) -> list[UserRead]:
    result = await session.execute(select(User).order_by(User.created_at))
    return [UserRead.from_model(u) for u in result.scalars().all()]
