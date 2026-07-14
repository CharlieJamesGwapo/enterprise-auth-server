"""Redis-backed fixed-window rate limiting and brute-force lockout."""

from __future__ import annotations

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.core.config import settings
from app.core.exceptions import AccountLocked, RateLimited, ServiceUnavailable
from app.core.logging import get_logger

logger = get_logger(__name__)


class RateLimiter:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    async def hit(self, key: str, limit: int, window_seconds: int = 60) -> None:
        """Increment a fixed-window counter; raise RateLimited when over limit.

        Fails CLOSED: if Redis is unreachable we cannot verify the limit, so we
        deny the request with ServiceUnavailable rather than let it through.
        """
        redis_key = f"ratelimit:{key}"
        try:
            count = await self.redis.incr(redis_key)
            if count == 1:
                await self.redis.expire(redis_key, window_seconds)
        except (RedisError, ConnectionError) as exc:
            logger.error("rate_limit_redis_unavailable", exc_info=exc)
            raise ServiceUnavailable() from exc
        if count > limit:
            raise RateLimited()

    # --- Brute-force account lockout ---
    def _lockout_key(self, identifier: str, ip: str | None = None) -> str:
        return f"lockout:{self._scoped(identifier, ip)}"

    def _failcount_key(self, identifier: str, ip: str | None = None) -> str:
        return f"failcount:{self._scoped(identifier, ip)}"

    @staticmethod
    def _scoped(identifier: str, ip: str | None) -> str:
        identifier = identifier.lower()
        return f"{identifier}:{ip}" if ip else identifier

    async def ensure_not_locked(self, identifier: str, ip: str | None = None) -> None:
        """Raise AccountLocked if locked, or ServiceUnavailable if Redis is down.

        Fails CLOSED: if we cannot check lock state, we cannot safely allow the
        login attempt through, so deny it.
        """
        try:
            locked = await self.redis.exists(self._lockout_key(identifier, ip))
        except (RedisError, ConnectionError) as exc:
            logger.error("lockout_check_redis_unavailable", exc_info=exc)
            raise ServiceUnavailable() from exc
        if locked:
            raise AccountLocked()

    async def record_failure(self, identifier: str, ip: str | None = None) -> None:
        """Best-effort: swallow Redis errors, the auth decision already happened."""
        key = self._failcount_key(identifier, ip)
        try:
            count = await self.redis.incr(key)
            if count == 1:
                await self.redis.expire(key, settings.LOCKOUT_SECONDS)
            if count >= settings.MAX_FAILED_LOGINS:
                await self.redis.set(
                    self._lockout_key(identifier, ip), "1", ex=settings.LOCKOUT_SECONDS
                )
                await self.redis.delete(key)
        except (RedisError, ConnectionError) as exc:
            logger.error("record_failure_redis_unavailable", exc_info=exc)

    async def clear_failures(self, identifier: str, ip: str | None = None) -> None:
        """Best-effort: swallow Redis errors, the auth decision already happened."""
        try:
            await self.redis.delete(self._failcount_key(identifier, ip))
            await self.redis.delete(self._lockout_key(identifier, ip))
        except (RedisError, ConnectionError) as exc:
            logger.error("clear_failures_redis_unavailable", exc_info=exc)
