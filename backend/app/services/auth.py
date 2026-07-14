"""Authentication service: registration and credential verification."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthError, ConflictError
from app.core.logging import get_logger
from app.core.security import hash_password, needs_rehash, verify_password
from app.models.user import User
from app.repositories.role import RoleRepository
from app.repositories.user import UserRepository
from app.services.rate_limit import RateLimiter

logger = get_logger(__name__)

DEFAULT_ROLE = "user"


class AuthService:
    def __init__(self, session: AsyncSession, rate_limiter: RateLimiter) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.roles = RoleRepository(session)
        self.rate_limiter = rate_limiter

    async def register(self, email: str, password: str, full_name: str = "") -> User:
        from app.core.passwords import validate_password_strength

        validate_password_strength(password)
        if await self.users.email_exists(email):
            raise ConflictError("A user with this email already exists.")
        user = User(
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name=full_name,
        )
        default_role = await self.roles.get_by_name(DEFAULT_ROLE)
        if default_role is not None:
            user.roles.append(default_role)
        await self.users.add(user)
        logger.info("user_registered", extra={"user_id": str(user.id)})
        return user

    async def authenticate(self, email: str, password: str) -> User:
        await self.rate_limiter.ensure_not_locked(email)
        user = await self.users.get_by_email(email)
        # Verify against the stored hash (or a dummy) to avoid user enumeration timing.
        stored = user.hashed_password if user else hash_password("invalid-placeholder")
        password_ok = verify_password(password, stored)

        if not user or not password_ok:
            await self.rate_limiter.record_failure(email)
            raise AuthError("Invalid email or password.")
        if not user.is_active:
            raise AuthError("This account is disabled.")

        await self.rate_limiter.clear_failures(email)
        if needs_rehash(user.hashed_password):
            user.hashed_password = hash_password(password)
            await self.session.flush()
        logger.info("user_authenticated", extra={"user_id": str(user.id)})
        return user
