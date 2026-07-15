"""Session repository."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select

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

    async def list_active_for_user(
        self, user_id: uuid.UUID, *, limit: int | None = None, offset: int = 0
    ) -> list[Session]:
        """All active sessions for a user, most recently active first.

        ``limit``/``offset`` default to None/0, which returns every active
        session — internal callers (e.g. logout-all) rely on this unpaginated
        behavior. Only the ``GET /sessions`` route passes explicit paging.
        """
        stmt = (
            select(Session)
            .where(Session.user_id == user_id, Session.is_active.is_(True))
            .order_by(Session.last_activity_at.desc())
            .offset(offset)
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_active_for_user(self, user_id: uuid.UUID) -> int:
        result = await self.session.execute(
            select(func.count())
            .select_from(Session)
            .where(Session.user_id == user_id, Session.is_active.is_(True))
        )
        return int(result.scalar_one())

    async def has_any_for_user(self, user_id: uuid.UUID) -> bool:
        """True if the user has any session at all (active or not)."""
        result = await self.session.execute(
            select(func.count()).select_from(Session).where(Session.user_id == user_id)
        )
        return int(result.scalar_one()) > 0

    async def has_matching_device(
        self,
        user_id: uuid.UUID,
        *,
        browser: str | None,
        operating_system: str | None,
        device_type: str | None,
    ) -> bool:
        """True if the user has any session (active or not) with this exact
        browser + operating_system + device_type combination.
        """
        result = await self.session.execute(
            select(func.count())
            .select_from(Session)
            .where(
                Session.user_id == user_id,
                Session.browser == browser,
                Session.operating_system == operating_system,
                Session.device_type == device_type,
            )
        )
        return int(result.scalar_one()) > 0
