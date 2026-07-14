"""OAuth provider abstraction and registry."""

from __future__ import annotations

from app.services.oauth.base import OAuthProvider, OAuthUserInfo
from app.services.oauth.registry import available_providers, get_provider

__all__ = ["OAuthProvider", "OAuthUserInfo", "get_provider", "available_providers"]
