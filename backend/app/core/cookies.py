"""Helpers for setting and clearing auth cookies consistently."""

from __future__ import annotations

from datetime import timedelta

from fastapi import Response

from app.core.config import settings
from app.services.token import TokenPair


def set_auth_cookies(response: Response, pair: TokenPair, csrf_token: str) -> None:
    common = {
        "httponly": True,
        "secure": settings.COOKIE_SECURE,
        "samesite": settings.COOKIE_SAMESITE,
        "domain": settings.COOKIE_DOMAIN,
    }
    response.set_cookie(
        settings.ACCESS_COOKIE_NAME,
        pair.access,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
        **common,
    )
    response.set_cookie(
        settings.REFRESH_COOKIE_NAME,
        pair.refresh,
        max_age=int(pair.refresh_ttl.total_seconds()),
        # Scope the refresh cookie to the refresh endpoint only.
        path=f"{settings.API_V1_PREFIX}/auth",
        **common,
    )
    # CSRF cookie is readable by JS (double-submit pattern) → not httpOnly.
    response.set_cookie(
        settings.CSRF_COOKIE_NAME,
        csrf_token,
        max_age=int(timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds()),
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        domain=settings.COOKIE_DOMAIN,
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    for name, path in (
        (settings.ACCESS_COOKIE_NAME, "/"),
        (settings.REFRESH_COOKIE_NAME, f"{settings.API_V1_PREFIX}/auth"),
        (settings.CSRF_COOKIE_NAME, "/"),
    ):
        response.delete_cookie(
            name, path=path, domain=settings.COOKIE_DOMAIN, samesite=settings.COOKIE_SAMESITE
        )
