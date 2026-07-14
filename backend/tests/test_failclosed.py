"""Fail-safe defaults: auth-critical ops fail CLOSED (503) on Redis outage,
while general traffic (the global rate-limit middleware) stays fail-OPEN.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

pytestmark = pytest.mark.asyncio

REG = {"email": "dana@example.com", "password": "S3curePass!word", "full_name": "Dana"}


def _break_redis(fake_redis, *, methods: tuple[str, ...]) -> None:
    """Make the given fakeredis methods raise a Redis ConnectionError."""
    for name in methods:
        setattr(fake_redis, name, AsyncMock(side_effect=RedisConnectionError("redis down")))


async def test_login_fails_closed_when_redis_down(client, fake_redis):
    await client.post("/api/v1/auth/register", json=REG)

    # Simulate Redis outage for the incr/exists calls the rate limiter relies on.
    _break_redis(fake_redis, methods=("incr", "exists"))

    resp = await client.post(
        "/api/v1/auth/login", json={"email": REG["email"], "password": REG["password"]}
    )
    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "service_unavailable"
    assert "detail" in body


async def test_general_traffic_fails_open_when_redis_down(client, fake_redis):
    _break_redis(fake_redis, methods=("incr", "exists"))

    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["detail"] == "ok"


async def test_ensure_not_locked_fails_closed_on_redis_error(fake_redis):
    from app.core.exceptions import ServiceUnavailable
    from app.services.rate_limit import RateLimiter

    _break_redis(fake_redis, methods=("exists",))
    limiter = RateLimiter(fake_redis)
    with pytest.raises(ServiceUnavailable):
        await limiter.ensure_not_locked("someone@example.com")


async def test_record_failure_and_clear_failures_swallow_redis_errors(fake_redis):
    """Best-effort post-auth bookkeeping must not raise/503 on Redis errors."""
    from app.services.rate_limit import RateLimiter

    _break_redis(fake_redis, methods=("incr", "delete"))
    limiter = RateLimiter(fake_redis)
    # Neither call should raise.
    await limiter.record_failure("someone@example.com")
    await limiter.clear_failures("someone@example.com")
