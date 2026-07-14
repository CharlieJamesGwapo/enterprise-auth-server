"""OAuth login and account-linking routes (Google, GitHub)."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Request, Response
from fastapi.responses import RedirectResponse

from app.api.v1.auth import _finalize_login
from app.dependencies.auth import CurrentUser
from app.dependencies.providers import (
    NotificationServiceDep,
    OAuthServiceDep,
    SessionServiceDep,
    TokenServiceDep,
)
from app.schemas.auth import AuthResponse
from app.schemas.common import Message
from app.schemas.oauth import OAuthLinkRead, ProvidersResponse
from app.services.oauth import available_providers

router = APIRouter(prefix="/auth/oauth", tags=["oauth"])


@router.get("/providers", response_model=ProvidersResponse)
async def list_providers() -> ProvidersResponse:
    """List the OAuth providers that are configured on this server."""
    return ProvidersResponse(providers=available_providers())


@router.get("/links", response_model=list[OAuthLinkRead])
async def list_links(user: CurrentUser, service: OAuthServiceDep) -> list[OAuthLinkRead]:
    """List the current user's linked OAuth accounts."""
    return [
        OAuthLinkRead(provider=a.provider, email=a.email, connected_at=a.created_at)
        for a in await service.list_links(user)
    ]


@router.get("/{provider}/authorize")
async def authorize(provider: str, service: OAuthServiceDep) -> RedirectResponse:
    """Begin an OAuth login: redirect the browser to the provider."""
    url = await service.start_authorization(provider, mode="login")
    return RedirectResponse(url, status_code=307)


@router.get("/{provider}/link")
async def link(provider: str, user: CurrentUser, service: OAuthServiceDep) -> RedirectResponse:
    """Begin linking a provider to the authenticated account."""
    url = await service.start_authorization(provider, mode="link", link_user_id=str(user.id))
    return RedirectResponse(url, status_code=307)


@router.get("/{provider}/callback", response_model=AuthResponse | Message)
async def callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    service: OAuthServiceDep,
    tokens: TokenServiceDep,
    sessions: SessionServiceDep,
    notifications: NotificationServiceDep,
) -> AuthResponse | Message:
    """Handle the provider redirect: log in (or link) and issue a session."""
    user, mode = await service.handle_callback(provider, code, state)
    if mode == "link":
        return Message(detail=f"{provider} account linked.")
    return await _finalize_login(
        request,
        response,
        tokens,
        sessions,
        notifications,
        background,
        user,
        remember_me=False,
    )
