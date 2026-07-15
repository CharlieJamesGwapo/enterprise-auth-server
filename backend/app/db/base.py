"""Declarative base and common model mixins."""

from __future__ import annotations

import uuid
from datetime import datetime

import uuid6
from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.types import GUID


class Base(DeclarativeBase):
    pass


class UUIDMixin:
    # uuid7 is time-ordered, which keeps B-tree inserts sequential (unlike
    # random uuid4) while remaining a drop-in `uuid.UUID` for the GUID type.
    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid6.uuid7)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
