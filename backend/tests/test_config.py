"""Settings validation: production must not run with built-in dev secrets."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings

VALID_FERNET_KEY = "UoK8YgRnrn-ZFVGqeN9NwdWty6t9VXKXyTgxlYxCqsU="


def test_production_with_dev_defaults_is_rejected():
    with pytest.raises((ValidationError, ValueError)):
        Settings(ENV="production")


def test_production_with_real_secrets_succeeds():
    settings = Settings(
        ENV="production",
        SECRET_KEY="x" * 40,
        ENCRYPTION_KEY=VALID_FERNET_KEY,
    )
    assert settings.ENV == "production"


def test_test_env_with_defaults_succeeds():
    settings = Settings(ENV="test")
    assert settings.ENV == "test"
