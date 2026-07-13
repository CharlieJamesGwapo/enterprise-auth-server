"""Session repository."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models.session import Session
from app.repositories.base import BaseRepository


class SessionRepository(BaseRepository[Session]):
    model = Session

    async def get_by_uuid(self, session_uuid: uuid.UUID) -> Session | None:
        result = await self.session.execute(
            select(Session).where(Session.session_uuid == session_uuid)
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: uuid.UUID, *, active_only: bool = True) -> list[Session]:
        stmt = select(Session).where(Session.user_id == user_id)
        if active_only:
            stmt = stmt.where(Session.is_active.is_(True))
        stmt = stmt.order_by(Session.last_activity_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def list_active_for_user(self, user_id: uuid.UUID) -> list[Session]:
        return await self.list_for_user(user_id, active_only=True)
