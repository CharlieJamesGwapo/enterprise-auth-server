"""Email-flow request schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class TokenRequest(BaseModel):
    token: str = Field(min_length=16, max_length=128, examples=["Xk9...urlsafe-token"])


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=16, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class ChangeEmailRequest(BaseModel):
    new_email: EmailStr
    password: str = Field(min_length=1, max_length=128)
