"""Concrete Google and GitHub OAuth providers."""

from __future__ import annotations

import httpx

from app.core.exceptions import AuthError
from app.services.oauth.base import OAuthProvider, OAuthUserInfo

_TIMEOUT = httpx.Timeout(10.0)


class GoogleProvider(OAuthProvider):
    name = "google"
    uses_pkce = True
    authorize_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    scope = "openid email profile"
    _token_url = "https://oauth2.googleapis.com/token"
    _userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> str:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            data["code_verifier"] = code_verifier
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(self._token_url, data=data)
        if resp.status_code != 200:
            raise AuthError("Failed to exchange Google authorization code.")
        return resp.json()["access_token"]

    async def fetch_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                self._userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if resp.status_code != 200:
            raise AuthError("Failed to fetch Google profile.")
        data = resp.json()
        return OAuthUserInfo(
            provider=self.name,
            account_id=str(data["sub"]),
            email=data.get("email"),
            name=data.get("name", ""),
            email_verified=bool(data.get("email_verified", False)),
        )


class GitHubProvider(OAuthProvider):
    name = "github"
    uses_pkce = False
    authorize_endpoint = "https://github.com/login/oauth/authorize"
    scope = "read:user user:email"
    _token_url = "https://github.com/login/oauth/access_token"
    _user_url = "https://api.github.com/user"
    _emails_url = "https://api.github.com/user/emails"

    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> str:
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": redirect_uri,
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                self._token_url, data=data, headers={"Accept": "application/json"}
            )
        if resp.status_code != 200 or "access_token" not in resp.json():
            raise AuthError("Failed to exchange GitHub authorization code.")
        return resp.json()["access_token"]

    async def fetch_user_info(self, access_token: str) -> OAuthUserInfo:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(self._user_url, headers=headers)
            if resp.status_code != 200:
                raise AuthError("Failed to fetch GitHub profile.")
            profile = resp.json()
            email = profile.get("email")
            email_verified = False
            if email is None:
                emails_resp = await client.get(self._emails_url, headers=headers)
                if emails_resp.status_code == 200:
                    primary = next((e for e in emails_resp.json() if e.get("primary")), None)
                    if primary:
                        email = primary.get("email")
                        email_verified = bool(primary.get("verified"))
        return OAuthUserInfo(
            provider=self.name,
            account_id=str(profile["id"]),
            email=email,
            name=profile.get("name") or profile.get("login", ""),
            email_verified=email_verified,
        )
