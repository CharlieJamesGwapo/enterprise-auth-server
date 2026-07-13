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
    SessionServiceDep,
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


async def _finalize_login(
    request: Request,
    response: Response,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
    user,
    remember_me: bool,
) -> AuthResponse:
    """Issue a session: mint tokens bound to a new session id and persist it."""
    session_uuid = uuid.uuid4()
    pair, refresh_jti = tokens.issue_pair(
        str(user.id), remember_me=remember_me, session_id=str(session_uuid)
    )
    await sessions.create_session(
        user=user,
        session_uuid=session_uuid,
        refresh_jti=refresh_jti,
        remember_me=remember_me,
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        headers=dict(request.headers),
    )
    await sessions.session.commit()
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
    request: Request,
    response: Response,
    session: DbSession,
    limiter: RateLimiterDep,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
) -> AuthResponse:
    service = AuthService(session, limiter)
    user = await service.register(payload.email, payload.password, payload.full_name)
    await session.flush()
    return await _finalize_login(request, response, tokens, sessions, user, remember_me=False)


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
    request: Request,
    response: Response,
    session: DbSession,
    limiter: RateLimiterDep,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
    sessions: SessionServiceDep,
) -> AuthResponse | LoginChallengeResponse:
    service = AuthService(session, limiter)
    user = await service.authenticate(payload.email, payload.password)
    await session.commit()

    # 2FA gate: never issue a session before the second factor is proven.
    if await twofa.is_enabled(user):
        audit("login_2fa_challenge", user_id=str(user.id))
        return LoginChallengeResponse(pre_auth_token=tokens.issue_pre_auth(str(user.id)))

    return await _finalize_login(
        request, response, tokens, sessions, user, remember_me=payload.remember_me
    )


@router.post("/login/otp", response_model=AuthResponse, dependencies=[Depends(_auth_rate_limit)])
async def login_otp(
    payload: OtpLoginRequest,
    request: Request,
    response: Response,
    session: DbSession,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
    sessions: SessionServiceDep,
) -> AuthResponse:
    """Complete a 2FA login by exchanging the pre-auth token + OTP for a session."""
    user_id = tokens.verify_pre_auth(payload.pre_auth_token)
    user = await _load_user_for_otp(session, user_id)
    await twofa.verify_totp(user, payload.otp)
    await session.commit()
    audit("login_2fa_otp_success", user_id=str(user.id))
    return await _finalize_login(
        request, response, tokens, sessions, user, remember_me=payload.remember_me
    )


@router.post(
    "/login/recovery-code",
    response_model=AuthResponse,
    dependencies=[Depends(_auth_rate_limit)],
)
async def login_recovery_code(
    payload: RecoveryLoginRequest,
    request: Request,
    response: Response,
    session: DbSession,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
    sessions: SessionServiceDep,
) -> AuthResponse:
    """Complete a 2FA login using a one-time recovery code."""
    user_id = tokens.verify_pre_auth(payload.pre_auth_token)
    user = await _load_user_for_otp(session, user_id)
    await twofa.consume_recovery_code(user, payload.recovery_code)
    await session.commit()
    audit("login_2fa_recovery_success", user_id=str(user.id))
    return await _finalize_login(
        request, response, tokens, sessions, user, remember_me=payload.remember_me
    )


@router.post("/refresh", response_model=Message)
async def refresh(
    request: Request,
    response: Response,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
) -> Message:
    token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not token:
        raise AuthError("Missing refresh token.")
    user_id, sid, pair, refresh_jti = await tokens.rotate(token)
    if sid:
        # Keep the session bound to the rotated refresh token (also enforces that
        # the session is still active — a revoked session cannot refresh).
        await sessions.rebind_refresh(uuid.UUID(user_id), uuid.UUID(sid), refresh_jti)
    csrf = generate_csrf_token()
    set_auth_cookies(response, pair, csrf)
    return Message(detail="refreshed")


@router.post("/logout", response_model=Message, dependencies=[Depends(verify_csrf)])
async def logout(
    request: Request,
    response: Response,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
) -> Message:
    token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if token:
        try:
            payload = await tokens.verify_refresh(token)
            await tokens.revoke(payload)
            sid = payload.get("sid")
            if sid:
                record = await sessions.repo.get_by_uuid(uuid.UUID(sid))
                if record is not None and record.is_active:
                    await sessions.revoke(record, reason="logout")
                    await sessions.session.commit()
        except AuthError:
            pass  # Already invalid — clearing cookies is enough.
    clear_auth_cookies(response)
    return Message(detail="logged out")


@router.get("/me", response_model=UserRead)
async def me(user: CurrentUser) -> UserRead:
    return UserRead.from_model(user)
