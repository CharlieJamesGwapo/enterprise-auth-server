"""Repositories for two-factor auth and backup codes."""

from __future__ import annotations

import uuid

from sqlalchemy import delete, func, select

from app.models.two_factor import BackupCode, TwoFactorAuth
from app.repositories.base import BaseRepository


class TwoFactorRepository(BaseRepository[TwoFactorAuth]):
    model = TwoFactorAuth

    async def get_by_user(self, user_id: uuid.UUID) -> TwoFactorAuth | None:
        result = await self.session.execute(
            select(TwoFactorAuth).where(TwoFactorAuth.user_id == user_id)
        )
        return result.scalar_one_or_none()


class BackupCodeRepository(BaseRepository[BackupCode]):
    model = BackupCode

    async def list_unused(self, user_id: uuid.UUID) -> list[BackupCode]:
        result = await self.session.execute(
            select(BackupCode).where(BackupCode.user_id == user_id, BackupCode.used_at.is_(None))
        )
        return list(result.scalars().all())

    async def count_unused(self, user_id: uuid.UUID) -> int:
        result = await self.session.execute(
            select(func.count())
            .select_from(BackupCode)
            .where(BackupCode.user_id == user_id, BackupCode.used_at.is_(None))
        )
        return int(result.scalar_one())

    async def delete_for_user(self, user_id: uuid.UUID) -> None:
        await self.session.execute(delete(BackupCode).where(BackupCode.user_id == user_id))
        await self.session.flush()
