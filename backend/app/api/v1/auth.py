"""Authentication routes. Routes delegate to services; no business logic here."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, Request, Response, status

from app.api.v1._login import _finalize_login
from app.core.audit import audit
from app.core.config import settings
from app.core.cookies import clear_auth_cookies, set_auth_cookies
from app.core.exceptions import AuthError, TokenReplayError
from app.core.security import decode_token, generate_csrf_token
from app.dependencies.auth import CurrentUser, verify_csrf
from app.dependencies.providers import (
    AuthServiceDep,
    DbSession,
    EmailAccountServiceDep,
    NotificationServiceDep,
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
    background: BackgroundTasks,
    auth_service: AuthServiceDep,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
    notifications: NotificationServiceDep,
    email_service: EmailAccountServiceDep,
) -> AuthResponse:
    user = await auth_service.register(payload.email, payload.password, payload.full_name)
    await auth_service.session.flush()
    result = await _finalize_login(
        request,
        response,
        tokens,
        sessions,
        notifications,
        background,
        user,
        remember_me=False,
    )
    await email_service.send_signup_emails(user, background)
    return result


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
    background: BackgroundTasks,
    auth_service: AuthServiceDep,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
    sessions: SessionServiceDep,
    notifications: NotificationServiceDep,
) -> AuthResponse | LoginChallengeResponse:
    user = await auth_service.authenticate(payload.email, payload.password, ip=client_ip(request))

    # 2FA gate: never issue a session before the second factor is proven.
    if await twofa.is_enabled(user):
        audit("login_2fa_challenge", user_id=str(user.id))
        return LoginChallengeResponse(pre_auth_token=tokens.issue_pre_auth(str(user.id)))

    return await _finalize_login(
        request,
        response,
        tokens,
        sessions,
        notifications,
        background,
        user,
        remember_me=payload.remember_me,
    )


@router.post("/login/otp", response_model=AuthResponse, dependencies=[Depends(_auth_rate_limit)])
async def login_otp(
    payload: OtpLoginRequest,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    session: DbSession,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
    sessions: SessionServiceDep,
    notifications: NotificationServiceDep,
) -> AuthResponse:
    """Complete a 2FA login by exchanging the pre-auth token + OTP for a session."""
    user_id = tokens.verify_pre_auth(payload.pre_auth_token)
    user = await _load_user_for_otp(session, user_id)
    await twofa.verify_totp(user, payload.otp)
    audit("login_2fa_otp_success", user_id=str(user.id))
    return await _finalize_login(
        request,
        response,
        tokens,
        sessions,
        notifications,
        background,
        user,
        remember_me=payload.remember_me,
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
    background: BackgroundTasks,
    session: DbSession,
    tokens: TokenServiceDep,
    twofa: TwoFactorServiceDep,
    sessions: SessionServiceDep,
    notifications: NotificationServiceDep,
) -> AuthResponse:
    """Complete a 2FA login using a one-time recovery code."""
    user_id = tokens.verify_pre_auth(payload.pre_auth_token)
    user = await _load_user_for_otp(session, user_id)
    await twofa.consume_recovery_code(user, payload.recovery_code)
    audit("login_2fa_recovery_success", user_id=str(user.id))
    return await _finalize_login(
        request,
        response,
        tokens,
        sessions,
        notifications,
        background,
        user,
        remember_me=payload.remember_me,
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
    try:
        user_id, sid, pair, refresh_jti = await tokens.rotate(token)
    except TokenReplayError as exc:
        await _handle_refresh_replay(token, sessions)
        raise AuthError(str(exc)) from exc
    if sid:
        # Keep the session bound to the rotated refresh token (also enforces that
        # the session is still active — a revoked session cannot refresh).
        await sessions.rebind_refresh(uuid.UUID(user_id), uuid.UUID(sid), refresh_jti)
    csrf = generate_csrf_token()
    set_auth_cookies(response, pair, csrf)
    return Message(detail="refreshed")


async def _handle_refresh_replay(token: str, sessions: SessionServiceDep) -> None:
    """A blacklisted (already-rotated) refresh token was replayed.

    This is a signal of token theft: the legitimate user already rotated this
    token, so whoever presented it again is not the legitimate holder. Kill
    the whole session/family rather than just rejecting this one request.
    """
    try:
        payload = decode_token(token, expected_type="refresh")
    except Exception:
        return
    sid = payload.get("sid")
    if not sid:
        return
    record = await sessions.revoke_by_sid(sid, reason="refresh_replay")
    if record is not None:
        # Commit the family revocation before the route re-raises 401 — otherwise
        # the end-of-request rollback would discard it, leaving the session active
        # in the DB (Redis alone would carry the revocation).
        await sessions.session.commit()
        audit(
            "refresh_replay_detected",
            user_id=str(record.user_id),
            session=str(record.session_uuid),
        )


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
        except AuthError:
            pass  # Already invalid — clearing cookies is enough.
    clear_auth_cookies(response)
    return Message(detail="logged out")


@router.get("/me", response_model=UserRead)
async def me(user: CurrentUser) -> UserRead:
    return UserRead.from_model(user)
