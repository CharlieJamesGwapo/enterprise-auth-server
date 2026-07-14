"""OAuth account repository."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.models.oauth_account import OAuthAccount
from app.repositories.base import BaseRepository


class OAuthAccountRepository(BaseRepository[OAuthAccount]):
    model = OAuthAccount

    async def get_by_provider_account(
        self, provider: str, provider_account_id: str
    ) -> OAuthAccount | None:
        result = await self.session.execute(
            select(OAuthAccount).where(
                OAuthAccount.provider == provider,
                OAuthAccount.provider_account_id == provider_account_id,
            )
        )
        return result.scalar_one_or_none()

    async def list_for_user(self, user_id: uuid.UUID) -> list[OAuthAccount]:
        result = await self.session.execute(
            select(OAuthAccount).where(OAuthAccount.user_id == user_id)
        )
        return list(result.scalars().all())
