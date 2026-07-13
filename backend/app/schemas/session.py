"""Session-related response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class SessionRead(BaseModel):
    session_id: uuid.UUID = Field(examples=["3f9a1b2c-4d5e-6f70-8192-a3b4c5d6e7f8"])
    device: str = Field(examples=["macOS Desktop"])
    device_type: str = Field(examples=["Desktop"])
    browser: str = Field(examples=["Chrome"])
    browser_version: str = Field(examples=["120.0.0"])
    os: str = Field(examples=["macOS"])
    os_version: str = Field(examples=["14.2"])
    ip: str = Field(examples=["203.0.113.7"])
    country: str | None = Field(default=None, examples=["Philippines"])
    city: str | None = Field(default=None, examples=["Cebu"])
    login_at: datetime
    last_activity: datetime
    current: bool = Field(description="True if this is the session making the request.")
    status: str = Field(examples=["active"])


class LastLoginRead(BaseModel):
    """Details of the most recent *previous* login (not the current one)."""

    previous_login_at: datetime | None = None
    previous_login_ip: str | None = None
    previous_device: str | None = None
    previous_browser: str | None = None


class LogoutResponse(BaseModel):
    detail: str
    revoked_sessions: int = 1
