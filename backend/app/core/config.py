"""Application configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    ENV: Literal["local", "test", "production"] = "local"
    DEBUG: bool = False
    PROJECT_NAME: str = "Enterprise Auth Server"
    API_V1_PREFIX: str = "/api/v1"

    # --- Security / JWT ---
    SECRET_KEY: str = Field(
        default="CHANGE-ME-dev-only-secret-key-not-for-production-use-0123456789"
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REFRESH_TOKEN_REMEMBER_ME_DAYS: int = 30
    # Short-lived token issued between password success and OTP verification.
    PRE_AUTH_TOKEN_EXPIRE_MINUTES: int = 5

    # --- Two-Factor Authentication ---
    # Fernet key (urlsafe base64, 32 bytes) used to encrypt TOTP secrets at rest.
    ENCRYPTION_KEY: str = "_i3FjZl2n-cXVRZCTQE5z5DPJaDhNlXFDBso8tHTClA="
    TWO_FACTOR_ISSUER: str = "Enterprise Auth Server"
    TOTP_VALID_WINDOW: int = 1  # accept ±1 time-step (30s each)
    BACKUP_CODE_COUNT: int = 10
    TWO_FA_RATE_LIMIT_PER_MINUTE: int = 5
    TWO_FA_MAX_FAILURES: int = 5

    # --- Sessions ---
    # Session is invalidated if idle longer than this (last activity → now).
    SESSION_IDLE_TIMEOUT_MINUTES: int = 30
    # Absolute cap on session lifetime regardless of activity (hours).
    SESSION_ABSOLUTE_EXPIRE_HOURS: int = 720  # 30 days
    # Seconds between persisted activity updates (write throttling).
    SESSION_ACTIVITY_THROTTLE_SECONDS: int = 10

    # --- Cookies ---
    COOKIE_SECURE: bool = True
    COOKIE_DOMAIN: str | None = None
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    ACCESS_COOKIE_NAME: str = "access_token"
    REFRESH_COOKIE_NAME: str = "refresh_token"
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    # --- Database ---
    DATABASE_URL: str = "postgresql+asyncpg://auth:auth@localhost:5432/auth"

    # --- Redis ---
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- CORS ---
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # --- Rate limiting / lockout ---
    RATE_LIMIT_PER_MINUTE: int = 60
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_SECONDS: int = 900

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors(cls, v: object) -> object:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
