"""Email verification, password reset, and email-change routes."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Request

from app.core.config import settings
from app.dependencies.auth import CurrentUser
from app.dependencies.providers import EmailAccountServiceDep, RateLimiterDep
from app.middleware.rate_limit import client_ip
from app.schemas.common import Message
from app.schemas.email import (
    ChangeEmailRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    TokenRequest,
)

router = APIRouter(prefix="/auth", tags=["email"])


async def _email_rate_limit(request: Request, limiter: RateLimiterDep) -> None:
    await limiter.hit(f"email:{client_ip(request)}", settings.AUTH_RATE_LIMIT_PER_MINUTE, 60)


@router.post("/verify-email", response_model=Message)
async def verify_email(payload: TokenRequest, service: EmailAccountServiceDep) -> Message:
    """Confirm an email address using the token from the verification email."""
    await service.verify_email(payload.token)
    return Message(detail="Email verified.")


@router.post("/resend-verification", response_model=Message)
async def resend_verification(
    background: BackgroundTasks, user: CurrentUser, service: EmailAccountServiceDep
) -> Message:
    """Resend the verification email to the authenticated user."""
    await service.resend_verification(user, background)
    return Message(detail="Verification email sent.")


@router.post(
    "/forgot-password",
    response_model=Message,
    dependencies=[Depends(_email_rate_limit)],
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    background: BackgroundTasks,
    service: EmailAccountServiceDep,
) -> Message:
    """Start a password reset. Always returns 200 to avoid account enumeration."""
    await service.request_password_reset(payload.email, background)
    return Message(detail="If that account exists, a reset email has been sent.")


@router.post(
    "/reset-password",
    response_model=Message,
    dependencies=[Depends(_email_rate_limit)],
)
async def reset_password(
    payload: ResetPasswordRequest,
    background: BackgroundTasks,
    service: EmailAccountServiceDep,
) -> Message:
    """Set a new password using a valid reset token."""
    await service.reset_password(payload.token, payload.new_password, background)
    return Message(detail="Password has been reset.")


@router.post("/change-email", response_model=Message)
async def change_email(
    payload: ChangeEmailRequest,
    background: BackgroundTasks,
    user: CurrentUser,
    service: EmailAccountServiceDep,
) -> Message:
    """Request an email change; a confirmation link is sent to the new address."""
    await service.request_email_change(user, payload.new_email, payload.password, background)
    return Message(detail="Confirmation email sent to the new address.")


@router.post("/confirm-email-change", response_model=Message)
async def confirm_email_change(payload: TokenRequest, service: EmailAccountServiceDep) -> Message:
    """Confirm and apply a pending email change."""
    await service.confirm_email_change(payload.token)
    return Message(detail="Email address updated.")
