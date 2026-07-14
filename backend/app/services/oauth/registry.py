"""Resolve configured OAuth providers from settings."""

from __future__ import annotations

from app.core.config import settings
from app.services.oauth.base import OAuthProvider
from app.services.oauth.providers import GitHubProvider, GoogleProvider


def get_provider(name: str) -> OAuthProvider | None:
    """Return a configured provider instance, or None if not configured/unknown."""
    if name == "google" and settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET:
        return GoogleProvider(settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET)
    if name == "github" and settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET:
        return GitHubProvider(settings.GITHUB_CLIENT_ID, settings.GITHUB_CLIENT_SECRET)
    return None


def available_providers() -> list[str]:
    return [name for name in ("google", "github") if get_provider(name) is not None]
