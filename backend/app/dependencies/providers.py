"""Shared FastAPI dependency providers (DB session, Redis, services)."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.redis.client import get_redis
from app.services.rate_limit import RateLimiter
from app.services.session import SessionService
from app.services.token import TokenService
from app.services.two_factor import TwoFactorService


async def db_dependency() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db():
        yield session


def redis_dependency() -> Redis:
    return get_redis()


DbSession = Annotated[AsyncSession, Depends(db_dependency)]
RedisClient = Annotated[Redis, Depends(redis_dependency)]


def get_rate_limiter(redis: RedisClient) -> RateLimiter:
    return RateLimiter(redis)


def get_token_service(redis: RedisClient) -> TokenService:
    return TokenService(redis)


def get_two_factor_service(session: DbSession, redis: RedisClient) -> TwoFactorService:
    return TwoFactorService(session, redis)


def get_session_service(session: DbSession, redis: RedisClient) -> SessionService:
    return SessionService(session, redis, TokenService(redis))


RateLimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
TokenServiceDep = Annotated[TokenService, Depends(get_token_service)]
TwoFactorServiceDep = Annotated[TwoFactorService, Depends(get_two_factor_service)]
SessionServiceDep = Annotated[SessionService, Depends(get_session_service)]
