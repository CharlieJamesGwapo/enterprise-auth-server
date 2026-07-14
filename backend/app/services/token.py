"""Token service: issue/rotate/revoke JWTs with a Redis-backed blacklist."""

from __future__ import annotations

from datetime import UTC, timedelta

import jwt
from redis.asyncio import Redis

from app.core.config import settings
from app.core.exceptions import AuthError, TokenReplayError
from app.core.security import create_token, decode_token

_BLACKLIST_PREFIX = "revoked_jti:"


class TokenPair:
    def __init__(self, access: str, refresh: str, refresh_ttl: timedelta) -> None:
        self.access = access
        self.refresh = refresh
        self.refresh_ttl = refresh_ttl


class TokenService:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    def _refresh_ttl(self, remember_me: bool) -> timedelta:
        days = (
            settings.REFRESH_TOKEN_REMEMBER_ME_DAYS
            if remember_me
            else settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        return timedelta(days=days)

    def issue_pair(
        self, user_id: str, remember_me: bool = False, session_id: str | None = None
    ) -> tuple[TokenPair, str]:
        """Issue an access+refresh pair bound to ``session_id``.

        Returns (pair, refresh_jti) so the caller can persist the refresh JTI on
        the session for targeted revocation.
        """
        claims = {"sid": session_id} if session_id else {}
        access, _ = create_token(
            user_id,
            "access",
            timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
            extra_claims=claims,
        )
        refresh_ttl = self._refresh_ttl(remember_me)
        refresh, refresh_jti = create_token(
            user_id,
            "refresh",
            refresh_ttl,
            extra_claims={"remember_me": remember_me, **claims},
        )
        return TokenPair(access, refresh, refresh_ttl), refresh_jti

    def issue_pre_auth(self, user_id: str) -> str:
        """Issue a short-lived token proving password success, pending OTP."""
        token, _ = create_token(
            user_id,
            "pre_auth",
            timedelta(minutes=settings.PRE_AUTH_TOKEN_EXPIRE_MINUTES),
        )
        return token

    def verify_pre_auth(self, token: str) -> str:
        """Validate a pre-auth token and return its subject (user id)."""
        try:
            payload = decode_token(token, expected_type="pre_auth")
        except jwt.PyJWTError as exc:
            raise AuthError("Invalid or expired pre-authentication token.") from exc
        return payload["sub"]

    async def _is_revoked(self, jti: str) -> bool:
        return bool(await self.redis.exists(f"{_BLACKLIST_PREFIX}{jti}"))

    async def revoke(self, payload: dict) -> None:
        """Blacklist a token's JTI until its natural expiry."""
        jti = payload.get("jti")
        exp = payload.get("exp")
        if not jti or not exp:
            return
        from datetime import datetime

        ttl = int(exp - datetime.now(UTC).timestamp())
        if ttl > 0:
            await self.redis.set(f"{_BLACKLIST_PREFIX}{jti}", "1", ex=ttl)

    async def revoke_jti(self, jti: str, ttl_seconds: int | None = None) -> None:
        """Blacklist a refresh JTI by value (used when only the JTI is known)."""
        if not jti:
            return
        ttl = ttl_seconds or int(self._refresh_ttl(remember_me=True).total_seconds())
        await self.redis.set(f"{_BLACKLIST_PREFIX}{jti}", "1", ex=ttl)

    def verify_access(self, token: str) -> dict:
        try:
            return decode_token(token, expected_type="access")
        except jwt.PyJWTError as exc:
            raise AuthError("Invalid or expired access token.") from exc

    async def verify_refresh(self, token: str) -> dict:
        try:
            payload = decode_token(token, expected_type="refresh")
        except jwt.PyJWTError as exc:
            raise AuthError("Invalid or expired refresh token.") from exc
        if await self._is_revoked(payload["jti"]):
            # The JTI is only blacklisted once it has already been rotated (see
            # `rotate`/`revoke`), so this means an old, already-used refresh
            # token is being replayed — a signal of theft, not just expiry.
            raise TokenReplayError()
        return payload

    async def rotate(self, refresh_token: str) -> tuple[str, str | None, TokenPair, str]:
        """Validate a refresh token, blacklist it, and issue a fresh pair.

        Returns (user_id, session_id, new_pair, new_refresh_jti). The session id
        is carried over so the rotated pair stays bound to the same session.
        """
        payload = await self.verify_refresh(refresh_token)
        await self.revoke(payload)
        user_id = payload["sub"]
        session_id = payload.get("sid")
        remember_me = bool(payload.get("remember_me", False))
        pair, refresh_jti = self.issue_pair(user_id, remember_me=remember_me, session_id=session_id)
        return user_id, session_id, pair, refresh_jti
