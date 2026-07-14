"""OAuth login/linking orchestration."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import audit
from app.core.config import settings
from app.core.exceptions import AuthError, ConflictError, NotFoundError
from app.core.security import hash_password
from app.models.oauth_account import OAuthAccount
from app.models.user import User
from app.repositories.oauth_account import OAuthAccountRepository
from app.repositories.role import RoleRepository
from app.repositories.user import UserRepository
from app.services.oauth import registry

_STATE_KEY = "oauth_state:{state}"
_DEFAULT_ROLE = "user"


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


class OAuthService:
    def __init__(self, session: AsyncSession, redis: Redis) -> None:
        self.session = session
        self.redis = redis
        self.accounts = OAuthAccountRepository(session)
        self.users = UserRepository(session)
        self.roles = RoleRepository(session)

    def _redirect_uri(self, provider: str) -> str:
        base = f"{settings.OAUTH_REDIRECT_BASE_URL}{settings.API_V1_PREFIX}"
        return f"{base}/auth/oauth/{provider}/callback"

    def _provider_or_404(self, name: str):
        provider = registry.get_provider(name)
        if provider is None:
            raise NotFoundError(f"OAuth provider '{name}' is not available.")
        return provider

    # ------------------------------------------------------ authorization
    async def start_authorization(
        self, provider_name: str, *, mode: str = "login", link_user_id: str | None = None
    ) -> str:
        provider = self._provider_or_404(provider_name)
        state = secrets.token_urlsafe(24)
        code_verifier = secrets.token_urlsafe(48) if provider.uses_pkce else None
        payload = {
            "provider": provider_name,
            "code_verifier": code_verifier,
            "mode": mode,
            "link_user_id": link_user_id,
        }
        await self.redis.set(
            _STATE_KEY.format(state=state),
            json.dumps(payload),
            ex=settings.OAUTH_STATE_TTL_SECONDS,
        )
        challenge = _pkce_challenge(code_verifier) if code_verifier else None
        return provider.authorization_url(state, self._redirect_uri(provider_name), challenge)

    async def _pop_state(self, state: str, provider_name: str) -> dict:
        raw = await self.redis.get(_STATE_KEY.format(state=state))
        if raw is None:
            raise AuthError("Invalid or expired OAuth state.")
        await self.redis.delete(_STATE_KEY.format(state=state))
        payload = json.loads(raw)
        if payload.get("provider") != provider_name:
            raise AuthError("OAuth state does not match provider.")
        return payload

    # ------------------------------------------------------------ callback
    async def handle_callback(self, provider_name: str, code: str, state: str) -> tuple[User, str]:
        payload = await self._pop_state(state, provider_name)
        provider = self._provider_or_404(provider_name)

        access_token = await provider.exchange_code(
            code, self._redirect_uri(provider_name), payload.get("code_verifier")
        )
        info = await provider.fetch_user_info(access_token)

        mode = payload.get("mode", "login")
        link_user_id = payload.get("link_user_id")
        account = await self.accounts.get_by_provider_account(provider_name, info.account_id)

        if account is not None:
            if mode == "link" and link_user_id and str(account.user_id) != link_user_id:
                raise ConflictError("This provider account is already linked to another user.")
            user = await self.users.get(account.user_id)
            if user is None:
                raise AuthError("Linked account no longer exists.")
            audit("oauth_login", user_id=str(user.id), provider=provider_name)
            return user, mode

        user = await self._resolve_user(info, mode, link_user_id)
        self.session.add(
            OAuthAccount(
                user_id=user.id,
                provider=provider_name,
                provider_account_id=info.account_id,
                email=info.email,
            )
        )
        await self.session.commit()
        audit(
            "oauth_account_linked" if mode == "link" else "oauth_signup",
            user_id=str(user.id),
            provider=provider_name,
        )
        return user, mode

    async def _resolve_user(self, info, mode: str, link_user_id: str | None) -> User:
        if mode == "link" and link_user_id:
            user = await self.users.get(uuid.UUID(link_user_id))
            if user is None:
                raise AuthError("Account to link no longer exists.")
            return user

        if not info.email:
            raise AuthError("The provider did not return an email address.")

        existing = await self.users.get_by_email(info.email)
        if existing is not None:
            if info.email_verified and existing.is_verified:
                return existing  # auto-link by matching email
            raise ConflictError(
                "An account with this email already exists. Sign in with your password "
                f"and link {info.provider} from account settings."
            )

        # Create a fresh account for this OAuth identity.
        user = User(
            email=info.email.lower(),
            hashed_password=hash_password(secrets.token_urlsafe(32)),
            full_name=info.name or "",
            is_verified=info.email_verified,
        )
        default_role = await self.roles.get_by_name(_DEFAULT_ROLE)
        if default_role is not None:
            user.roles.append(default_role)
        await self.users.add(user)
        return user

    async def list_links(self, user: User) -> list[OAuthAccount]:
        return await self.accounts.list_for_user(user.id)
