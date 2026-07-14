"""Session service: creation, validation, activity tracking, and revocation.

Postgres is authoritative for session state; Redis provides a fast per-session
revocation flag and an activity-write throttle. Access/refresh JWTs carry the
session's ``sid`` so a revoked or expired session immediately invalidates them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import audit
from app.core.config import settings
from app.core.exceptions import AuthError, NotFoundError
from app.core.useragent import parse_user_agent
from app.models.session import Session
from app.models.user import User
from app.repositories.session import SessionRepository
from app.services.geoip import resolve_location
from app.services.token import TokenService

_REVOKED_KEY = "session_revoked:{sid}"
_TOUCH_KEY = "session_touch:{sid}"


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime) -> datetime:
    """Treat naive datetimes (e.g. from SQLite) as UTC for safe comparison."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


class SessionService:
    def __init__(self, session: AsyncSession, redis: Redis, token_service: TokenService) -> None:
        self.session = session
        self.redis = redis
        self.tokens = token_service
        self.repo = SessionRepository(session)

    # ------------------------------------------------------------- lifetimes
    def _expiry(self, remember_me: bool) -> datetime:
        refresh_days = (
            settings.REFRESH_TOKEN_REMEMBER_ME_DAYS
            if remember_me
            else settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        absolute = timedelta(hours=settings.SESSION_ABSOLUTE_EXPIRE_HOURS)
        return _now() + min(timedelta(days=refresh_days), absolute)

    # --------------------------------------------------------------- create
    async def create_session(
        self,
        *,
        user: User,
        session_uuid: uuid.UUID,
        refresh_jti: str,
        remember_me: bool,
        ip: str,
        user_agent: str,
        headers: dict[str, str],
    ) -> tuple[Session, bool]:
        """Create a session. Returns (session, is_new_device)."""
        device = parse_user_agent(user_agent)
        geo = resolve_location(ip, headers)
        now = _now()

        prior = await self.repo.list_for_user(user.id, active_only=False)
        is_new_device = bool(prior) and not any(
            s.browser == device.browser
            and s.operating_system == device.operating_system
            and s.device_type == device.device_type
            for s in prior
        )

        record = Session(
            user_id=user.id,
            session_uuid=session_uuid,
            refresh_token_id=refresh_jti,
            device_name=device.device_name,
            device_type=device.device_type,
            browser=device.browser,
            browser_version=device.browser_version,
            operating_system=device.operating_system,
            operating_system_version=device.operating_system_version,
            user_agent=device.user_agent,
            ip_address=ip,
            country=geo.country,
            city=geo.city,
            login_at=now,
            last_activity_at=now,
            expires_at=self._expiry(remember_me),
            is_active=True,
            request_count=0,
        )
        await self.repo.add(record)

        await self._set_active(session_uuid)
        audit("session_created", user_id=str(user.id), session=str(session_uuid), ip=ip)
        if is_new_device:
            audit(
                "new_device_login",
                user_id=str(user.id),
                session=str(session_uuid),
                device=device.device_name,
                browser=device.browser,
                country=geo.country,
            )
        return record, is_new_device

    # ------------------------------------------------------- validate/touch
    async def validate_and_touch(self, session_uuid: uuid.UUID, user_id: uuid.UUID) -> Session:
        """Return the active session, enforcing revocation/idle/absolute expiry."""
        if await self.redis.exists(_REVOKED_KEY.format(sid=session_uuid)):
            raise AuthError("Session has been revoked.")

        record = await self.repo.get_by_uuid(session_uuid)
        if record is None or record.user_id != user_id or not record.is_active:
            raise AuthError("Session is no longer valid.")

        now = _now()
        if now >= _aware(record.expires_at):
            await self._expire(record, "absolute_expiry")
            raise AuthError("Session has expired.")

        idle_cutoff = _aware(record.last_activity_at) + timedelta(
            minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES
        )
        if now > idle_cutoff:
            await self._expire(record, "idle_timeout")
            raise AuthError("Session expired due to inactivity.")

        await self._touch(record, now)
        return record

    async def _touch(self, record: Session, now: datetime) -> None:
        """Throttled activity update: last_activity + request_count."""
        throttle_key = _TOUCH_KEY.format(sid=record.session_uuid)
        if await self.redis.exists(throttle_key):
            return
        record.last_activity_at = now
        record.request_count += 1
        await self.session.commit()
        await self.redis.set(throttle_key, "1", ex=settings.SESSION_ACTIVITY_THROTTLE_SECONDS)
        await self._set_active(record.session_uuid)

    # ------------------------------------------------------------- revoke
    async def _expire(self, record: Session, reason: str) -> None:
        record.is_active = False
        record.logout_at = _now()
        record.logout_reason = reason
        await self.session.commit()
        await self._clear_cache(record.session_uuid, revoke=True)
        audit(
            "session_expired",
            user_id=str(record.user_id),
            session=str(record.session_uuid),
            reason=reason,
        )

    async def revoke(self, record: Session, *, reason: str) -> None:
        record.is_active = False
        record.logout_at = _now()
        record.logout_reason = reason
        await self.tokens.revoke_jti(record.refresh_token_id)
        await self.session.flush()
        await self._clear_cache(record.session_uuid, revoke=True)
        audit(
            "session_revoked",
            user_id=str(record.user_id),
            session=str(record.session_uuid),
            reason=reason,
        )

    async def revoke_by_uuid(self, user: User, session_uuid: uuid.UUID, *, reason: str) -> Session:
        record = await self.repo.get_by_uuid(session_uuid)
        if record is None or record.user_id != user.id:
            raise NotFoundError("Session not found.")
        if record.is_active:
            await self.revoke(record, reason=reason)
        return record

    async def revoke_by_sid(self, sid: str, *, reason: str) -> Session | None:
        """Revoke a session by its raw uuid string, no ownership check.

        Used for refresh-token replay handling: the caller has already proven
        possession of a (now-revoked) refresh token bound to this session, so
        no additional ownership check is needed. Returns the session record if
        one was found and active, else None.
        """
        try:
            session_uuid = uuid.UUID(sid)
        except ValueError:
            return None
        record = await self.repo.get_by_uuid(session_uuid)
        if record is None or not record.is_active:
            return None
        await self.revoke(record, reason=reason)
        return record

    async def revoke_all(
        self, user: User, *, reason: str, except_uuid: uuid.UUID | None = None
    ) -> int:
        sessions = await self.repo.list_active_for_user(user.id)
        count = 0
        for record in sessions:
            if except_uuid is not None and record.session_uuid == except_uuid:
                continue
            await self.revoke(record, reason=reason)
            count += 1
        audit("logout_all_devices", user_id=str(user.id), revoked=count)
        return count

    async def rebind_refresh(
        self, user_id: uuid.UUID, session_uuid: uuid.UUID, new_refresh_jti: str
    ) -> None:
        """After refresh rotation, point the session at the new refresh JTI."""
        record = await self.repo.get_by_uuid(session_uuid)
        if record is None or not record.is_active or record.user_id != user_id:
            raise AuthError("Session is no longer valid.")
        record.refresh_token_id = new_refresh_jti
        record.last_activity_at = _now()
        await self.session.commit()
        await self._set_active(session_uuid)
        audit("token_refresh", user_id=str(user_id), session=str(session_uuid))

    # ------------------------------------------------------------- queries
    async def list_active(self, user: User) -> list[Session]:
        return await self.repo.list_active_for_user(user.id)

    async def get_owned(self, user: User, session_uuid: uuid.UUID) -> Session:
        record = await self.repo.get_by_uuid(session_uuid)
        if record is None or record.user_id != user.id:
            raise NotFoundError("Session not found.")
        return record

    async def previous_login(self, user: User, current: Session | None) -> Session | None:
        """Most recent session that logged in before the current one."""
        sessions = await self.repo.list_for_user(user.id, active_only=False)
        cutoff = _aware(current.login_at) if current else _now()
        current_uuid = current.session_uuid if current else None
        candidates = [
            s for s in sessions if s.session_uuid != current_uuid and _aware(s.login_at) < cutoff
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda s: s.login_at)

    # ------------------------------------------------------------- redis
    async def _set_active(self, session_uuid: uuid.UUID) -> None:
        ttl = settings.SESSION_IDLE_TIMEOUT_MINUTES * 60
        await self.redis.set(f"session_active:{session_uuid}", "1", ex=ttl)

    async def _clear_cache(self, session_uuid: uuid.UUID, *, revoke: bool) -> None:
        await self.redis.delete(f"session_active:{session_uuid}")
        await self.redis.delete(_TOUCH_KEY.format(sid=session_uuid))
        if revoke:
            ttl = settings.SESSION_ABSOLUTE_EXPIRE_HOURS * 3600
            await self.redis.set(_REVOKED_KEY.format(sid=session_uuid), "1", ex=ttl)
