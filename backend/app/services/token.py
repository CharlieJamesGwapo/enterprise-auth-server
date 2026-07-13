"""Token service: issue/rotate/revoke JWTs with a Redis-backed blacklist."""

from __future__ import annotations

from datetime import UTC, timedelta

import jwt
from redis.asyncio import Redis

from app.core.config import settings
from app.core.exceptions import AuthError
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

    def issue_pair(self, user_id: str, remember_me: bool = False) -> TokenPair:
        access, _ = create_token(
            user_id, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        refresh_ttl = self._refresh_ttl(remember_me)
        refresh, _ = create_token(
            user_id, "refresh", refresh_ttl, extra_claims={"remember_me": remember_me}
        )
        return TokenPair(access, refresh, refresh_ttl)

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
            await self.redis.setex(f"{_BLACKLIST_PREFIX}{jti}", ttl, "1")

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
            raise AuthError("Refresh token has been revoked.")
        return payload

    async def rotate(self, refresh_token: str) -> tuple[str, TokenPair]:
        """Validate a refresh token, blacklist it, and issue a fresh pair.

        Returns (user_id, new_pair).
        """
        payload = await self.verify_refresh(refresh_token)
        await self.revoke(payload)
        user_id = payload["sub"]
        remember_me = bool(payload.get("remember_me", False))
        return user_id, self.issue_pair(user_id, remember_me=remember_me)
