"""Authentication request/response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, EmailStr, Field

from app.schemas.user import UserRead


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    remember_me: bool = False


class AuthResponse(BaseModel):
    """Body returned on successful auth. Tokens themselves ride in httpOnly cookies."""

    user: UserRead
    csrf_token: str


class LoginChallengeResponse(BaseModel):
    """Returned when the account has 2FA enabled: no session is issued yet."""

    otp_required: Literal[True] = True
    pre_auth_token: str = Field(
        description="Short-lived token to exchange for a session via /login/otp "
        "or /login/recovery-code.",
    )


class OtpLoginRequest(BaseModel):
    pre_auth_token: str
    otp: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$", examples=["123456"])
    remember_me: bool = False


class RecoveryLoginRequest(BaseModel):
    pre_auth_token: str
    recovery_code: str = Field(min_length=8, max_length=32, examples=["A82J-KQ91-XR7T"])
    remember_me: bool = False
