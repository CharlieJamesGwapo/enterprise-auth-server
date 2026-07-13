"""Health and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.dependencies.providers import DbSession, RedisClient
from app.schemas.common import Message

router = APIRouter(tags=["health"])


@router.get("/health", response_model=Message)
async def health() -> Message:
    return Message(detail="ok")


@router.get("/ready", response_model=Message)
async def ready(session: DbSession, redis: RedisClient) -> Message:
    await session.execute(text("SELECT 1"))
    await redis.ping()
    return Message(detail="ready")
