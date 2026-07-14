"""OAuth response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class OAuthLinkRead(BaseModel):
    provider: str
    email: str | None
    connected_at: datetime


class ProvidersResponse(BaseModel):
    providers: list[str]
