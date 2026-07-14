"""Two-factor authentication management routes (authenticated user)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.audit import audit
from app.core.config import settings
from app.dependencies.auth import CurrentUser, verify_csrf
from app.dependencies.providers import RateLimiterDep, TwoFactorServiceDep
from app.middleware.rate_limit import client_ip
from app.schemas.two_factor import (
    DisableRequest,
    OtpVerifyRequest,
    PasswordConfirm,
    RecoveryCodesRequest,
    RecoveryCodesResponse,
    SetupResponse,
    SuccessResponse,
    TwoFactorStatus,
)

router = APIRouter(prefix="/auth/2fa", tags=["2fa"])


async def _twofa_rate_limit(request: Request, user: CurrentUser, limiter: RateLimiterDep) -> None:
    """Rate-limit sensitive 2FA operations per user and per IP."""
    await limiter.hit(f"2fa:{user.id}", settings.TWO_FA_RATE_LIMIT_PER_MINUTE, 60)
    await limiter.hit(f"2fa-ip:{client_ip(request)}", settings.TWO_FA_RATE_LIMIT_PER_MINUTE * 3, 60)


@router.get("/status", response_model=TwoFactorStatus)
async def status_endpoint(user: CurrentUser, service: TwoFactorServiceDep) -> TwoFactorStatus:
    """Report whether 2FA is enabled and how many recovery codes remain."""
    return TwoFactorStatus(**await service.status(user))


@router.post(
    "/setup",
    response_model=SetupResponse,
    dependencies=[Depends(_twofa_rate_limit), Depends(verify_csrf)],
)
async def setup(
    payload: PasswordConfirm,
    user: CurrentUser,
    service: TwoFactorServiceDep,
) -> SetupResponse:
    """Begin 2FA setup: verify password, mint a secret, return QR + provisioning URI.

    2FA does NOT become active here — the user must confirm via ``/verify``.
    """
    secret, uri = await service.start_setup(user, payload.password)
    await service.session.commit()
    audit("2fa_setup_started", user_id=str(user.id))
    return SetupResponse(
        provisioning_uri=uri,
        qr_code_base64=service.qr_code_base64(uri),
        secret=secret,
    )


@router.post(
    "/verify",
    response_model=SuccessResponse,
    dependencies=[Depends(_twofa_rate_limit), Depends(verify_csrf)],
)
async def verify(
    payload: OtpVerifyRequest,
    user: CurrentUser,
    service: TwoFactorServiceDep,
) -> SuccessResponse:
    """Verify the first OTP and activate 2FA."""
    await service.confirm_setup(user, payload.otp)
    await service.session.commit()
    audit("2fa_enabled", user_id=str(user.id))
    return SuccessResponse()


@router.get("/qrcode")
async def qrcode(user: CurrentUser, service: TwoFactorServiceDep) -> Response:
    """Return the pending setup's QR code as a PNG image."""
    secret = await service.get_pending_secret(user)
    uri = service.provisioning_uri(secret, user.email)
    return Response(content=service.qr_code_png(uri), media_type="image/png")


@router.post(
    "/recovery-codes",
    response_model=RecoveryCodesResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_twofa_rate_limit), Depends(verify_csrf)],
)
async def recovery_codes(
    payload: RecoveryCodesRequest,
    user: CurrentUser,
    service: TwoFactorServiceDep,
) -> RecoveryCodesResponse:
    """Generate the initial set of recovery codes (fails if some already exist)."""
    service.require_password(user, payload.password)
    await service.verify_totp(user, payload.otp)
    codes = await service.generate_recovery_codes(user, replace=False)
    await service.session.commit()
    audit("2fa_recovery_codes_generated", user_id=str(user.id))
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post(
    "/recovery-codes/regenerate",
    response_model=RecoveryCodesResponse,
    dependencies=[Depends(_twofa_rate_limit), Depends(verify_csrf)],
)
async def regenerate_recovery_codes(
    payload: RecoveryCodesRequest,
    user: CurrentUser,
    service: TwoFactorServiceDep,
) -> RecoveryCodesResponse:
    """Delete existing recovery codes and issue a fresh set."""
    service.require_password(user, payload.password)
    await service.verify_totp(user, payload.otp)
    codes = await service.generate_recovery_codes(user, replace=True)
    await service.session.commit()
    audit("2fa_recovery_codes_regenerated", user_id=str(user.id))
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post(
    "/disable",
    response_model=SuccessResponse,
    dependencies=[Depends(_twofa_rate_limit), Depends(verify_csrf)],
)
async def disable(
    payload: DisableRequest,
    user: CurrentUser,
    service: TwoFactorServiceDep,
) -> SuccessResponse:
    """Disable 2FA (requires current password AND a valid OTP)."""
    await service.disable(user, payload.password, payload.otp)
    await service.session.commit()
    audit("2fa_disabled", user_id=str(user.id))
    return SuccessResponse()
