"""Authentication routes. Routes delegate to services; no business logic here."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.audit import audit
from app.core.config import settings
from app.core.cookies import clear_auth_cookies, set_auth_cookies
from app.core.exceptions import AuthError
from app.core.security import generate_csrf_token
from app.dependencies.auth import CurrentUser, verify_csrf
from app.dependencies.providers import (
    DbSession,
    RateLimiterDep,
    TokenServiceDep,
    TwoFactorServiceDep,
)
from app.middleware.rate_limit import client_ip
from app.repositories.user import UserRepository
from app.schemas.auth import (
    AuthResponse,
    LoginChallengeResponse,
    LoginRequest,
    OtpLoginRequest,
    RecoveryLoginRequest,
    RegisterRequest,
)
from app.schemas.common import Message
from app.schemas.user import UserRead
from app.services.auth import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])


async def _load_user_for_otp(session: DbSession, user_id: str):
    try:
        user = await UserRepository(session).get(uuid.UUID(user_id))
    except ValueError as exc:
        raise AuthError("Invalid pre-authentication token.") from exc
    if user is None or not user.is_active:
        raise AuthError("Account is unavailable.")
    return user


async def _auth_rate_limit(request: Request, limiter: RateLimiterDep) -> None:
    await limiter.hit(f"auth:{client_ip(request)}", settings.AUTH_RATE_LIMIT_PER_MINUTE, 60)


def _finalize_login(response: Response, tokens: TokenServiceDep, user, remember_me: bool):
    pair = tokens.issue_pair(str(user.id), remember_me=remember_me)
    csrf = generate_csrf_token()
    set_auth_cookies(response, pair, csrf)
    return AuthResponse(user=UserRead.from_model(user), csrf_token=csrf)


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_auth_rate_limit)],
)
async def register(
    payload: RegisterRequest,
    response: Response,
    session: DbSession,
    limiter: RateLimiterDep,
    tokens: TokenServiceDep,
) -> AuthResponse:
    service = AuthService(session, limiter)
    user = await service.register(payload.email, payload.password, payload.full_name)
    await session.commit()
    return _finalize_login(response, tokens, user, remember_me=False)


@router.post(
    "/login",
    response_model=AuthResponse | LoginChallengeResponse,
    dependencies=[Depends(_auth_rate_limit)],
    responses={
        200: {
            "description": "Session issued, or a 2FA challenge if the account "
            "has two-factor authentication enabled.",
        }
    },
)
async def login(
    payload: LoginRequest,
    response: Response,
    session: DbSession,
    limiter: RateLimiterDep,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
) -> AuthResponse | LoginChallengeResponse:
    service = AuthService(session, limiter)
    user = await service.authenticate(payload.email, payload.password)
    await session.commit()

    # 2FA gate: never issue a session before the second factor is proven.
    if await twofa.is_enabled(user):
        audit("login_2fa_challenge", user_id=str(user.id))
        return LoginChallengeResponse(pre_auth_token=tokens.issue_pre_auth(str(user.id)))

    return _finalize_login(response, tokens, user, remember_me=payload.remember_me)


@router.post("/login/otp", response_model=AuthResponse, dependencies=[Depends(_auth_rate_limit)])
async def login_otp(
    payload: OtpLoginRequest,
    response: Response,
    session: DbSession,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
) -> AuthResponse:
    """Complete a 2FA login by exchanging the pre-auth token + OTP for a session."""
    user_id = tokens.verify_pre_auth(payload.pre_auth_token)
    user = await _load_user_for_otp(session, user_id)
    await twofa.verify_totp(user, payload.otp)
    await session.commit()
    audit("login_2fa_otp_success", user_id=str(user.id))
    return _finalize_login(response, tokens, user, remember_me=payload.remember_me)


@router.post(
    "/login/recovery-code",
    response_model=AuthResponse,
    dependencies=[Depends(_auth_rate_limit)],
)
async def login_recovery_code(
    payload: RecoveryLoginRequest,
    response: Response,
    session: DbSession,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
) -> AuthResponse:
    """Complete a 2FA login using a one-time recovery code."""
    user_id = tokens.verify_pre_auth(payload.pre_auth_token)
    user = await _load_user_for_otp(session, user_id)
    await twofa.consume_recovery_code(user, payload.recovery_code)
    await session.commit()
    audit("login_2fa_recovery_success", user_id=str(user.id))
    return _finalize_login(response, tokens, user, remember_me=payload.remember_me)


@router.post("/refresh", response_model=Message)
async def refresh(
    request: Request,
    response: Response,
    tokens: TokenServiceDep,
) -> Message:
    token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not token:
        raise AuthError("Missing refresh token.")
    _user_id, pair = await tokens.rotate(token)
    csrf = generate_csrf_token()
    set_auth_cookies(response, pair, csrf)
    return Message(detail="refreshed")


@router.post("/logout", response_model=Message, dependencies=[Depends(verify_csrf)])
async def logout(request: Request, response: Response, tokens: TokenServiceDep) -> Message:
    token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if token:
        try:
            payload = await tokens.verify_refresh(token)
            await tokens.revoke(payload)
        except AuthError:
            pass  # Already invalid — clearing cookies is enough.
    clear_auth_cookies(response)
    return Message(detail="logged out")


@router.get("/me", response_model=UserRead)
async def me(user: CurrentUser) -> UserRead:
    return UserRead.from_model(user)
