"""Abstract OAuth2 authorization-code provider."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass(frozen=True)
class OAuthUserInfo:
    provider: str
    account_id: str
    email: str | None
    name: str
    email_verified: bool


class OAuthProvider(ABC):
    name: str
    uses_pkce: bool = False
    authorize_endpoint: str
    scope: str

    def __init__(self, client_id: str, client_secret: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret

    def authorization_url(
        self, state: str, redirect_uri: str, code_challenge: str | None = None
    ) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self.scope,
            "state": state,
        }
        if self.uses_pkce and code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self.authorize_endpoint}?{urlencode(params)}"

    @abstractmethod
    async def exchange_code(
        self, code: str, redirect_uri: str, code_verifier: str | None = None
    ) -> str:
        """Exchange an authorization code for an access token."""

    @abstractmethod
    async def fetch_user_info(self, access_token: str) -> OAuthUserInfo:
        """Fetch the authenticated user's profile from the provider."""
