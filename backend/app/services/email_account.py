"""Email-driven account flows: verification, password reset, email change.

Owns email-token lifecycle (single-use, hashed, expiring) and the user-state
changes they authorize. Email delivery is scheduled on the request's
BackgroundTasks so responses never block on SMTP.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import audit
from app.core.config import settings
from app.core.exceptions import AuthError, ConflictError, ValidationError
from app.core.passwords import validate_password_strength
from app.core.security import hash_password, verify_password
from app.models.email_token import (
    PURPOSE_CHANGE_EMAIL,
    PURPOSE_RESET_PASSWORD,
    PURPOSE_VERIFY_EMAIL,
    EmailToken,
)
from app.models.user import User
from app.repositories.email_token import EmailTokenRepository
from app.repositories.user import UserRepository
from app.services.notifications import NotificationService


def _now() -> datetime:
    return datetime.now(UTC)


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class EmailAccountService:
    def __init__(self, session: AsyncSession, notifications: NotificationService) -> None:
        self.session = session
        self.notifications = notifications
        self.tokens = EmailTokenRepository(session)
        self.users = UserRepository(session)

    # ---------------------------------------------------------------- tokens
    async def _issue(
        self, user: User, purpose: str, ttl: timedelta, *, new_email: str | None = None
    ) -> str:
        # Only one active token per purpose; supersede any previous one.
        await self.tokens.delete_for_purpose(user.id, purpose)
        raw = secrets.token_urlsafe(32)
        token = EmailToken(
            user_id=user.id,
            token_hash=_hash_token(raw),
            purpose=purpose,
            new_email=new_email,
            expires_at=_now() + ttl,
        )
        await self.tokens.add(token)
        return raw

    async def _consume(self, raw: str, purpose: str) -> EmailToken:
        token = await self.tokens.get_by_hash(_hash_token(raw))
        if token is None or token.purpose != purpose or token.used_at is not None:
            raise AuthError("Invalid or already-used token.")
        expires = token.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if _now() >= expires:
            raise AuthError("This token has expired.")
        token.used_at = _now()
        await self.session.flush()
        return token

    # ------------------------------------------------------- email verification
    async def send_signup_emails(self, user: User, background: BackgroundTasks) -> None:
        raw = await self._issue(
            user,
            PURPOSE_VERIFY_EMAIL,
            timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS),
        )
        background.add_task(self.notifications.send_welcome, user.email, user.full_name)
        background.add_task(self.notifications.send_verification, user.email, raw)

    async def resend_verification(self, user: User, background: BackgroundTasks) -> None:
        if user.is_verified:
            raise ConflictError("Email is already verified.")
        raw = await self._issue(
            user,
            PURPOSE_VERIFY_EMAIL,
            timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS),
        )
        background.add_task(self.notifications.send_verification, user.email, raw)

    async def verify_email(self, raw: str) -> User:
        token = await self._consume(raw, PURPOSE_VERIFY_EMAIL)
        user = await self.users.get(token.user_id)
        if user is None:
            raise AuthError("Account no longer exists.")
        user.is_verified = True
        await self.session.flush()
        audit("email_verified", user_id=str(user.id))
        return user

    # ---------------------------------------------------------- password reset
    async def request_password_reset(self, email: str, background: BackgroundTasks) -> None:
        # Always succeed silently to avoid account enumeration.
        user = await self.users.get_by_email(email)
        if user is None or not user.is_active:
            return
        raw = await self._issue(
            user,
            PURPOSE_RESET_PASSWORD,
            timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES),
        )
        await self.session.flush()
        background.add_task(self.notifications.send_password_reset, user.email, raw)
        audit("password_reset_requested", user_id=str(user.id))

    async def reset_password(
        self, raw: str, new_password: str, background: BackgroundTasks
    ) -> User:
        validate_password_strength(new_password)
        token = await self._consume(raw, PURPOSE_RESET_PASSWORD)
        user = await self.users.get(token.user_id)
        if user is None:
            raise AuthError("Account no longer exists.")
        user.hashed_password = hash_password(new_password)
        await self.session.flush()
        background.add_task(self.notifications.send_password_changed, user.email)
        audit("password_reset_completed", user_id=str(user.id))
        return user

    # ------------------------------------------------------------ email change
    async def request_email_change(
        self, user: User, new_email: str, password: str, background: BackgroundTasks
    ) -> None:
        if not verify_password(password, user.hashed_password):
            raise AuthError("Password confirmation failed.")
        new_email = new_email.lower()
        if new_email == user.email:
            raise ValidationError("New email matches the current email.")
        if await self.users.email_exists(new_email):
            raise ConflictError("That email address is already in use.")
        raw = await self._issue(
            user,
            PURPOSE_CHANGE_EMAIL,
            timedelta(hours=settings.EMAIL_CHANGE_EXPIRE_HOURS),
            new_email=new_email,
        )
        await self.session.flush()
        background.add_task(self.notifications.send_email_change, new_email, raw)
        audit("email_change_requested", user_id=str(user.id))

    async def confirm_email_change(self, raw: str) -> User:
        token = await self._consume(raw, PURPOSE_CHANGE_EMAIL)
        user = await self.users.get(token.user_id)
        if user is None or token.new_email is None:
            raise AuthError("Invalid email-change token.")
        # Re-check availability at confirmation time.
        if await self.users.email_exists(token.new_email):
            raise ConflictError("That email address is already in use.")
        user.email = token.new_email
        user.is_verified = True
        await self.session.flush()
        audit("email_changed", user_id=str(user.id))
        return user
