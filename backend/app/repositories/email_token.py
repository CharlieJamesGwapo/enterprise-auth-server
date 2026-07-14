"""Email-token repository."""

from __future__ import annotations

import uuid

from sqlalchemy import delete, select

from app.models.email_token import EmailToken
from app.repositories.base import BaseRepository


class EmailTokenRepository(BaseRepository[EmailToken]):
    model = EmailToken

    async def get_by_hash(self, token_hash: str) -> EmailToken | None:
        result = await self.session.execute(
            select(EmailToken).where(EmailToken.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    async def delete_for_purpose(self, user_id: uuid.UUID, purpose: str) -> None:
        """Invalidate any outstanding tokens of a purpose (one active at a time)."""
        await self.session.execute(
            delete(EmailToken).where(EmailToken.user_id == user_id, EmailToken.purpose == purpose)
        )
        await self.session.flush()
