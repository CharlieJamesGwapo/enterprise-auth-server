"""Redis-backed fixed-window rate limiting and brute-force lockout."""

from __future__ import annotations

from redis.asyncio import Redis

from app.core.config import settings
from app.core.exceptions import AccountLocked, RateLimited


class RateLimiter:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def hit(self, key: str, limit: int, window_seconds: int = 60) -> None:
        """Increment a fixed-window counter; raise RateLimited when over limit."""
        redis_key = f"ratelimit:{key}"
        count = await self.redis.incr(redis_key)
        if count == 1:
            await self.redis.expire(redis_key, window_seconds)
        if count > limit:
            raise RateLimited()

    # --- Brute-force account lockout ---
    def _lockout_key(self, identifier: str) -> str:
        return f"lockout:{identifier.lower()}"

    async def ensure_not_locked(self, identifier: str) -> None:
        if await self.redis.exists(self._lockout_key(identifier)):
            raise AccountLocked()

    async def record_failure(self, identifier: str) -> None:
        key = f"failcount:{identifier.lower()}"
        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, settings.LOCKOUT_SECONDS)
        if count >= settings.MAX_FAILED_LOGINS:
            await self.redis.setex(self._lockout_key(identifier), settings.LOCKOUT_SECONDS, "1")
            await self.redis.delete(key)

    async def clear_failures(self, identifier: str) -> None:
        await self.redis.delete(f"failcount:{identifier.lower()}")
        await self.redis.delete(self._lockout_key(identifier))
