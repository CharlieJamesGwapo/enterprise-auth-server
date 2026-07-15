"""Two-factor authentication request/response schemas (Pydantic v2)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class PasswordConfirm(BaseModel):
    password: str = Field(min_length=1, max_length=128, examples=["S3curePass!word"])


class DisableRequest(PasswordConfirm):
    otp: str = Field(min_length=6, max_length=10, examples=["123456"])


class RecoveryCodesRequest(PasswordConfirm):
    otp: str = Field(min_length=6, max_length=10, examples=["123456"])


class OtpVerifyRequest(BaseModel):
    otp: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$", examples=["123456"])


class SetupResponse(BaseModel):
    """Returned when 2FA setup starts. Secret is delivered only as a QR/URI."""

    provisioning_uri: str = Field(
        examples=["otpauth://totp/Enterprise%20Auth%20Server:user@email.com?secret=..."]
    )
    qr_code_base64: str = Field(description="PNG QR code, base64-encoded (no data URI prefix).")
    secret: str = Field(
        description="Plaintext TOTP secret, shown ONCE for manual entry.",
        examples=["JBSWY3DPEHPK3PXP"],
    )


class RecoveryCodesResponse(BaseModel):
    """Recovery codes are returned in plaintext exactly once."""

    recovery_codes: list[str] = Field(examples=[["A82J-KQ91", "PL92-DKS1"]])


class TwoFactorStatus(BaseModel):
    enabled: bool
    verified_at: datetime | None = None
    recovery_codes_remaining: int = 0
