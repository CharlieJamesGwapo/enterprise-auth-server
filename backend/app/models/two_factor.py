"""Two-factor authentication models: TOTP secret and backup recovery codes."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.db.types import GUID


class TwoFactorAuth(UUIDMixin, TimestampMixin, Base):
    """One TOTP configuration per user (created on setup, activated on verify)."""

    __tablename__ = "two_factor_auth"

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True
    )
    # TOTP secret, encrypted at rest (Fernet). Never exposed after setup.
    encrypted_secret: Mapped[str] = mapped_column(String(512), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<TwoFactorAuth user={self.user_id} enabled={self.enabled}>"


class BackupCode(UUIDMixin, Base):
    """A single-use recovery code. Only the hash is stored; plaintext shown once."""

    __tablename__ = "backup_codes"

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    hashed_code: Mapped[str] = mapped_column(String(255), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    def __repr__(self) -> str:
        return f"<BackupCode user={self.user_id} used={self.is_used}>"
