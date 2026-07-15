"""Test data factories (Factory Boy + Faker).

Factories build unpersisted model instances; helpers persist them through the
repository/session so async I/O stays explicit.
"""

from __future__ import annotations

import factory
from argon2 import PasswordHasher
from faker import Faker
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.role import Role
from app.models.user import User

fake = Faker()

DEFAULT_PASSWORD = "S3curePass!word"

# Factories build model instances synchronously, so they can't `await` the
# threadpooled `app.core.security.hash_password`. Hash directly here with the
# same Argon2 params instead (kept in sync with app.core.security).
_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)


class UserFactory(factory.Factory):
    class Meta:
        model = User

    email = factory.LazyFunction(lambda: fake.unique.email())
    full_name = factory.LazyFunction(lambda: fake.name())
    hashed_password = factory.LazyFunction(lambda: _hasher.hash(DEFAULT_PASSWORD))
    is_active = True
    is_verified = True
    is_superuser = False


async def create_user(
    session: AsyncSession,
    *,
    role: str | None = "user",
    password: str = DEFAULT_PASSWORD,
    **overrides,
) -> User:
    user = UserFactory.build(hashed_password=_hasher.hash(password), **overrides)
    if role:
        db_role = (
            await session.execute(select(Role).where(Role.name == role))
        ).scalar_one_or_none()
        if db_role:
            user.roles.append(db_role)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user
