"""User session model for device/session tracking."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDMixin
from app.db.types import GUID


class Session(UUIDMixin, TimestampMixin, Base):
    """A single authenticated session (one per successful login)."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    session_uuid: Mapped[uuid.UUID] = mapped_column(
        GUID(), unique=True, index=True, default=uuid.uuid4, nullable=False
    )
    # JTI of the refresh token bound to this session (for targeted revocation).
    refresh_token_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    # --- Device / client metadata ---
    device_name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    device_type: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    browser: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    browser_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    operating_system: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    operating_system_version: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    user_agent: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), default="", nullable=False)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # --- Lifecycle ---
    login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    logout_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    logout_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    is_current: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    def __repr__(self) -> str:
        return f"<Session {self.session_uuid} user={self.user_id} active={self.is_active}>"
