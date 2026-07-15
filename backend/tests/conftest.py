"""Pytest fixtures: isolated SQLite DB + fakeredis, no external services."""

from __future__ import annotations

import os

# Must be set before app config is imported (settings are cached at import time).
os.environ.setdefault("ENV", "test")
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci-only-not-production-000000")
os.environ.setdefault("ENCRYPTION_KEY", "_i3FjZl2n-cXVRZCTQE5z5DPJaDhNlXFDBso8tHTClA=")
os.environ.setdefault("EMAIL_BACKEND", "memory")

from collections.abc import AsyncGenerator  # noqa: E402

import fakeredis.aioredis  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool  # noqa: E402

import app.redis.client as redis_client  # noqa: E402
from app.core.config import settings as _settings  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.seed import seed_rbac  # noqa: E402
from app.dependencies.providers import db_dependency, redis_dependency  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_outbox():
    """Reset the in-memory email outbox before each test."""
    from app.services.email.backends import OUTBOX

    OUTBOX.clear()
    yield
    OUTBOX.clear()


@pytest_asyncio.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session_factory(engine):
    return async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture
async def db_session(session_factory) -> AsyncGenerator[AsyncSession, None]:
    async with session_factory() as session:
        await seed_rbac(session)
        yield session


@pytest_asyncio.fixture
async def fake_redis():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    # Point the app's shared client at fakeredis (used by middleware + deps).
    redis_client._client = client
    yield client
    await client.flushall()
    redis_client._client = None


@pytest_asyncio.fixture
async def seeded_session(session_factory) -> AsyncGenerator[AsyncSession, None]:
    """A session on the shared engine with RBAC already seeded (for factories)."""
    async with session_factory() as session:
        await seed_rbac(session)
        yield session


@pytest_asyncio.fixture
async def client(session_factory, fake_redis) -> AsyncGenerator[AsyncClient, None]:
    async def _db_override() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as session:
            await seed_rbac(session)
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[db_dependency] = _db_override
    app.dependency_overrides[redis_dependency] = lambda: fake_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test", follow_redirects=True
    ) as ac:

        async def _csrf(request):
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                token = ac.cookies.get(_settings.CSRF_COOKIE_NAME)
                if token and _settings.CSRF_HEADER_NAME not in request.headers:
                    request.headers[_settings.CSRF_HEADER_NAME] = token

        ac.event_hooks["request"] = [_csrf]
        yield ac

    app.dependency_overrides.clear()
