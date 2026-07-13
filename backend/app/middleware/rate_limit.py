"""Global best-effort rate-limit middleware (per client IP)."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings
from app.core.logging import get_logger
from app.redis.client import get_redis
from app.services.rate_limit import RateLimiter

logger = get_logger(__name__)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        ip = client_ip(request)
        limiter = RateLimiter(get_redis())
        try:
            await limiter.hit(f"global:{ip}", settings.RATE_LIMIT_PER_MINUTE, 60)
        except Exception as exc:  # RateLimited or Redis unavailable
            from app.core.exceptions import RateLimited

            if isinstance(exc, RateLimited):
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate_limited", "detail": exc.message},
                )
            # Fail open if Redis is down, but log it as a security event.
            logger.error("rate_limit_backend_error", exc_info=exc)
        return await call_next(request)
