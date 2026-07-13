"""Two-factor authentication service (TOTP + backup recovery codes).

Encapsulates all 2FA business logic: secret generation/encryption, OTP
verification with replay protection and lockout, QR provisioning, and
single-use recovery codes. Routes stay thin and delegate here.
"""

from __future__ import annotations

import base64
import io
import secrets
from datetime import UTC, datetime

import pyotp
import qrcode
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.exceptions import AuthError, ConflictError, NotFoundError
from app.core.security import hash_password, verify_password
from app.models.two_factor import BackupCode, TwoFactorAuth
from app.models.user import User
from app.repositories.two_factor import BackupCodeRepository, TwoFactorRepository
from app.services.rate_limit import RateLimiter

# Unambiguous alphabet for recovery codes (no 0/O/1/I to avoid transcription errors).
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_OTP_STEP_SECONDS = 30


class TwoFactorService:
    def __init__(self, session: AsyncSession, redis: Redis) -> None:
        self.session = session
        self.redis = redis
        self.twofa = TwoFactorRepository(session)
        self.codes = BackupCodeRepository(session)
        self.rate_limiter = RateLimiter(redis)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _totp(secret: str) -> pyotp.TOTP:
        return pyotp.TOTP(secret)

    @staticmethod
    def require_password(user: User, password: str) -> None:
        if not verify_password(password, user.hashed_password):
            raise AuthError("Password confirmation failed.")

    def provisioning_uri(self, secret: str, email: str) -> str:
        return self._totp(secret).provisioning_uri(
            name=email, issuer_name=settings.TWO_FACTOR_ISSUER
        )

    @staticmethod
    def qr_code_base64(provisioning_uri: str) -> str:
        img = qrcode.make(provisioning_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return base64.b64encode(buffer.getvalue()).decode()

    def qr_code_png(self, provisioning_uri: str) -> bytes:
        img = qrcode.make(provisioning_uri)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    # ------------------------------------------------------------------- setup
    async def start_setup(self, user: User, password: str) -> tuple[str, str]:
        """Verify password, (re)create a pending secret. Returns (secret, uri)."""
        self.require_password(user, password)

        record = await self.twofa.get_by_user(user.id)
        if record is not None and record.enabled:
            raise ConflictError("Two-factor authentication is already enabled.")

        secret = pyotp.random_base32()
        if record is None:
            record = TwoFactorAuth(user_id=user.id, encrypted_secret=encrypt(secret), enabled=False)
            await self.twofa.add(record)
        else:
            # Overwrite an abandoned, unverified setup.
            record.encrypted_secret = encrypt(secret)
            record.enabled = False
            record.verified_at = None
        await self.session.flush()

        return secret, self.provisioning_uri(secret, user.email)

    async def get_pending_secret(self, user: User) -> str:
        record = await self.twofa.get_by_user(user.id)
        if record is None or record.enabled:
            raise NotFoundError("No pending two-factor setup to display.")
        return decrypt(record.encrypted_secret)

    async def confirm_setup(self, user: User, otp: str) -> None:
        """Activate 2FA once the user proves they can generate a valid OTP."""
        record = await self.twofa.get_by_user(user.id)
        if record is None:
            raise NotFoundError("Start two-factor setup first.")
        if record.enabled:
            raise ConflictError("Two-factor authentication is already enabled.")

        secret = decrypt(record.encrypted_secret)
        if not self._totp(secret).verify(otp, valid_window=settings.TOTP_VALID_WINDOW):
            raise AuthError("Invalid verification code.")

        record.enabled = True
        record.verified_at = datetime.now(UTC)
        await self.session.flush()

    # ------------------------------------------------------------- verification
    async def _enabled_record(self, user: User) -> TwoFactorAuth:
        record = await self.twofa.get_by_user(user.id)
        if record is None or not record.enabled:
            raise ConflictError("Two-factor authentication is not enabled.")
        return record

    async def verify_totp(self, user: User, otp: str) -> None:
        """Verify an OTP for an enabled account with lockout + replay protection."""
        lock_id = f"2fa:{user.id}"
        await self.rate_limiter.ensure_not_locked(lock_id)

        record = await self._enabled_record(user)
        secret = decrypt(record.encrypted_secret)

        replay_key = f"2fa_otp_used:{user.id}:{otp}"
        if await self.redis.exists(replay_key):
            await self.rate_limiter.record_failure(lock_id)
            raise AuthError("This code has already been used.")

        if not self._totp(secret).verify(otp, valid_window=settings.TOTP_VALID_WINDOW):
            await self.rate_limiter.record_failure(lock_id)
            raise AuthError("Invalid verification code.")

        # Mark the code consumed for its whole validity span to block replay.
        ttl = _OTP_STEP_SECONDS * (2 * settings.TOTP_VALID_WINDOW + 1)
        await self.redis.set(replay_key, "1", ex=ttl)
        await self.rate_limiter.clear_failures(lock_id)

    # --------------------------------------------------------- recovery codes
    @staticmethod
    def _generate_code() -> str:
        raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))
        return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"

    async def generate_recovery_codes(self, user: User, *, replace: bool) -> list[str]:
        existing = await self.codes.count_unused(user.id)
        if existing and not replace:
            raise ConflictError("Recovery codes already exist. Use regenerate to replace them.")
        if replace:
            await self.codes.delete_for_user(user.id)

        plaintext = [self._generate_code() for _ in range(settings.BACKUP_CODE_COUNT)]
        for code in plaintext:
            self.session.add(BackupCode(user_id=user.id, hashed_code=hash_password(code)))
        await self.session.flush()
        return plaintext

    async def consume_recovery_code(self, user: User, code: str) -> None:
        lock_id = f"2fa:{user.id}"
        await self.rate_limiter.ensure_not_locked(lock_id)

        normalized = code.strip().upper()
        for candidate in await self.codes.list_unused(user.id):
            if verify_password(normalized, candidate.hashed_code):
                candidate.used_at = datetime.now(UTC)
                await self.session.flush()
                await self.rate_limiter.clear_failures(lock_id)
                return
        await self.rate_limiter.record_failure(lock_id)
        raise AuthError("Invalid recovery code.")

    # -------------------------------------------------------------- disable
    async def disable(self, user: User, password: str, otp: str) -> None:
        self.require_password(user, password)
        await self.verify_totp(user, otp)
        record = await self.twofa.get_by_user(user.id)
        if record is not None:
            await self.twofa.delete(record)
        await self.codes.delete_for_user(user.id)
        await self.session.flush()

    # --------------------------------------------------------------- status
    async def is_enabled(self, user: User) -> bool:
        record = await self.twofa.get_by_user(user.id)
        return bool(record and record.enabled)

    async def status(self, user: User) -> dict[str, object]:
        record = await self.twofa.get_by_user(user.id)
        enabled = bool(record and record.enabled)
        return {
            "enabled": enabled,
            "verified_at": record.verified_at if record else None,
            "recovery_codes_remaining": (await self.codes.count_unused(user.id) if enabled else 0),
        }
