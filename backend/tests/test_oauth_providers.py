"""Real HTTP-layer tests for GoogleProvider/GitHubProvider using respx.

respx intercepts httpx at the transport layer, so it works even though each
provider method opens its own short-lived ``httpx.AsyncClient``.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from app.core.exceptions import AuthError
from app.services.oauth.providers import GitHubProvider, GoogleProvider

pytestmark = pytest.mark.asyncio


# ------------------------------------------------------------------- Google
@respx.mock
async def test_google_exchange_code_success():
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok"})
    )
    provider = GoogleProvider("cid", "secret")
    token = await provider.exchange_code("code123", "http://cb")
    assert token == "tok"


@respx.mock
async def test_google_exchange_code_with_code_verifier_success():
    route = respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok"})
    )
    provider = GoogleProvider("cid", "secret")
    token = await provider.exchange_code("code123", "http://cb", code_verifier="verifier-abc")
    assert token == "tok"
    sent = route.calls.last.request.content.decode()
    assert "code_verifier=verifier-abc" in sent


@respx.mock
async def test_google_exchange_code_non_200_raises():
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant"})
    )
    provider = GoogleProvider("cid", "secret")
    with pytest.raises(AuthError):
        await provider.exchange_code("bad-code", "http://cb")


@respx.mock
async def test_google_fetch_user_info_success():
    respx.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "12345",
                "email": "person@example.com",
                "name": "Person Name",
                "email_verified": True,
            },
        )
    )
    provider = GoogleProvider("cid", "secret")
    info = await provider.fetch_user_info("access-tok")
    assert info.provider == "google"
    assert info.account_id == "12345"
    assert info.email == "person@example.com"
    assert info.name == "Person Name"
    assert info.email_verified is True


@respx.mock
async def test_google_fetch_user_info_non_200_raises():
    respx.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(401, json={"error": "invalid_token"})
    )
    provider = GoogleProvider("cid", "secret")
    with pytest.raises(AuthError):
        await provider.fetch_user_info("bad-tok")


# ------------------------------------------------------------------- GitHub
@respx.mock
async def test_github_exchange_code_success():
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok"})
    )
    provider = GitHubProvider("cid", "secret")
    token = await provider.exchange_code("code123", "http://cb")
    assert token == "tok"


@respx.mock
async def test_github_exchange_code_missing_access_token_raises():
    respx.post("https://github.com/login/oauth/access_token").mock(
        return_value=httpx.Response(200, json={"error": "bad_verification_code"})
    )
    provider = GitHubProvider("cid", "secret")
    with pytest.raises(AuthError):
        await provider.exchange_code("bad-code", "http://cb")


@respx.mock
async def test_github_fetch_user_info_public_email():
    respx.get("https://api.github.com/user").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": 999,
                "email": "public@example.com",
                "name": "Gitty Hub",
                "login": "gitty",
            },
        )
    )
    provider = GitHubProvider("cid", "secret")
    info = await provider.fetch_user_info("access-tok")
    assert info.provider == "github"
    assert info.account_id == "999"
    assert info.email == "public@example.com"
    assert info.name == "Gitty Hub"
    # Public email on the profile itself is not asserted "verified" by GitHub.
    assert info.email_verified is False


@respx.mock
async def test_github_fetch_user_info_falls_back_to_emails_endpoint():
    respx.get("https://api.github.com/user").mock(
        return_value=httpx.Response(
            200,
            json={"id": 1000, "email": None, "name": None, "login": "noemail"},
        )
    )
    respx.get("https://api.github.com/user/emails").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"email": "secondary@example.com", "primary": False, "verified": True},
                {"email": "primary@example.com", "primary": True, "verified": True},
            ],
        )
    )
    provider = GitHubProvider("cid", "secret")
    info = await provider.fetch_user_info("access-tok")
    assert info.account_id == "1000"
    assert info.email == "primary@example.com"
    assert info.email_verified is True
    # No profile name or login-based name fallback -> falls back to login.
    assert info.name == "noemail"


@respx.mock
async def test_github_fetch_user_info_non_200_raises():
    respx.get("https://api.github.com/user").mock(
        return_value=httpx.Response(401, json={"message": "Bad credentials"})
    )
    provider = GitHubProvider("cid", "secret")
    with pytest.raises(AuthError):
        await provider.fetch_user_info("bad-tok")
