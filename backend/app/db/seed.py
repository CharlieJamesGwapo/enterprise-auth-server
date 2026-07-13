"""Idempotent seeding of RBAC roles and permissions."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models import PERMISSIONS, ROLES
from app.models.permission import Permission
from app.models.role import Role

logger = get_logger(__name__)


async def seed_rbac(session: AsyncSession) -> None:
    """Create any missing permissions/roles and wire up their relationships."""
    perms: dict[str, Permission] = {}
    for code, description in PERMISSIONS.items():
        existing = (
            await session.execute(select(Permission).where(Permission.code == code))
        ).scalar_one_or_none()
        if existing is None:
            existing = Permission(code=code, description=description)
            session.add(existing)
        perms[code] = existing
    await session.flush()

    for name, codes in ROLES.items():
        role = (await session.execute(select(Role).where(Role.name == name))).scalar_one_or_none()
        if role is None:
            role = Role(name=name, description=f"{name} role")
            session.add(role)
        role.permissions = [perms[c] for c in codes]
    await session.commit()
    logger.info("rbac_seeded", extra={"roles": list(ROLES), "permissions": list(PERMISSIONS)})
