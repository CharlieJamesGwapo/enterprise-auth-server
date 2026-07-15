"""OAuth tests: authorize redirect, login, signup, account linking (fake provider)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from app.services.oauth.base import OAuthUserInfo
from tests.factories import create_user

PASSWORD = "S3curePass!word"


class FakeProvider:
    """Stand-in provider that skips all network calls."""

    def __init__(self, name: str, info: OAuthUserInfo, uses_pkce: bool = False) -> None:
        self.name = name
        self.uses_pkce = uses_pkce
        self._info = info

    def authorization_url(self, state, redirect_uri, code_challenge=None):
        return f"https://fake-oauth.test/authorize?state={state}"

    async def exchange_code(self, code, redirect_uri, code_verifier=None):
        return "fake-access-token"

    async def fetch_user_info(self, access_token):
        return self._info


def install_provider(monkeypatch, *, name="google", info=None, configured=("google",)):
    info = info or OAuthUserInfo(
        provider=name,
        account_id="acct-123",
        email="oauth@example.com",
        name="OAuth User",
        email_verified=True,
    )
    fake = FakeProvider(name, info, uses_pkce=(name == "google"))

    def fake_get_provider(requested: str):
        return fake if requested in configured else None

    monkeypatch.setattr("app.services.oauth.registry.get_provider", fake_get_provider)
    return fake


async def _authorize(client, provider="google", path="authorize"):
    resp = await client.get(f"/api/v1/auth/oauth/{provider}/{path}", follow_redirects=False)
    return resp


def _state_from(resp) -> str:
    location = resp.headers["location"]
    return parse_qs(urlparse(location).query)["state"][0]


# ------------------------------------------------------------------ providers
async def test_providers_list(client, monkeypatch):
    install_provider(monkeypatch, configured=("google",))
    resp = await client.get("/api/v1/auth/oauth/providers")
    assert resp.status_code == 200
    assert resp.json()["providers"] == ["google"]


async def test_authorize_not_configured_is_404(client, monkeypatch):
    install_provider(monkeypatch, configured=())  # nothing configured
    resp = await _authorize(client, "google")
    assert resp.status_code == 404


# --------------------------------------------------------------------- login
async def test_authorize_redirects_to_provider(client, monkeypatch):
    install_provider(monkeypatch)
    resp = await _authorize(client)
    assert resp.status_code == 307
    assert resp.headers["location"].startswith("https://fake-oauth.test/authorize")


async def test_callback_creates_new_user_and_logs_in(client, monkeypatch):
    install_provider(monkeypatch)
    state = _state_from(await _authorize(client))
    resp = await client.get(f"/api/v1/auth/oauth/google/callback?code=abc&state={state}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["email"] == "oauth@example.com"
    # Verified email from the provider carries over.
    assert resp.json()["user"]["is_verified"] is True
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200


async def test_callback_links_existing_user_by_email(client, monkeypatch, seeded_session):
    # is_verified=True by default in the factory; provider also reports email_verified=True.
    await create_user(seeded_session, email="oauth@example.com", is_verified=True)
    install_provider(
        monkeypatch,
        info=OAuthUserInfo(
            provider="google",
            account_id="acct-123",
            email="oauth@example.com",
            name="OAuth User",
            email_verified=True,
        ),
    )
    state = _state_from(await _authorize(client))
    resp = await client.get(f"/api/v1/auth/oauth/google/callback?code=abc&state={state}")
    assert resp.status_code == 200
    # No new user created — logs in as the existing account.
    users = await client.get("/api/v1/auth/me")
    assert users.json()["email"] == "oauth@example.com"


async def test_callback_unverified_provider_email_does_not_take_over_account(
    client, monkeypatch, seeded_session
):
    """An attacker controlling a provider account with an unverified victim email
    must NOT be able to auto-link/login as the victim."""
    await create_user(seeded_session, email="victim@example.com", is_verified=True)
    install_provider(
        monkeypatch,
        info=OAuthUserInfo(
            provider="google",
            account_id="attacker-acct",
            email="victim@example.com",
            name="Attacker",
            email_verified=False,
        ),
    )
    state = _state_from(await _authorize(client))
    resp = await client.get(f"/api/v1/auth/oauth/google/callback?code=abc&state={state}")
    assert resp.status_code == 409
    assert resp.json()["error"] == "conflict"
    # Not logged in.
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 401


async def test_returning_oauth_user_reuses_account(client, monkeypatch):
    install_provider(monkeypatch)
    # First login creates the account.
    state1 = _state_from(await _authorize(client))
    await client.get(f"/api/v1/auth/oauth/google/callback?code=abc&state={state1}")
    # Second login finds the existing oauth_account.
    state2 = _state_from(await _authorize(client))
    resp = await client.get(f"/api/v1/auth/oauth/google/callback?code=xyz&state={state2}")
    assert resp.status_code == 200
    assert resp.json()["user"]["email"] == "oauth@example.com"


async def test_callback_invalid_state_rejected(client, monkeypatch):
    install_provider(monkeypatch)
    resp = await client.get("/api/v1/auth/oauth/google/callback?code=abc&state=bogus-state")
    assert resp.status_code == 401


async def test_callback_without_email_rejected(client, monkeypatch):
    install_provider(
        monkeypatch,
        info=OAuthUserInfo(
            provider="google",
            account_id="no-email",
            email=None,
            name="X",
            email_verified=False,
        ),
    )
    state = _state_from(await _authorize(client))
    resp = await client.get(f"/api/v1/auth/oauth/google/callback?code=abc&state={state}")
    assert resp.status_code == 401


# --------------------------------------------------------------------- linking
async def test_link_flow_connects_provider_to_account(client, monkeypatch):
    # Log in with a password account first.
    await client.post(
        "/api/v1/auth/register",
        json={"email": "owner@example.com", "password": PASSWORD, "full_name": "O"},
    )
    install_provider(
        monkeypatch,
        name="github",
        configured=("github",),
        info=OAuthUserInfo(
            provider="github",
            account_id="gh-1",
            email="owner@example.com",
            name="O",
            email_verified=True,
        ),
    )
    link_resp = await _authorize(client, "github", "link")
    assert link_resp.status_code == 307
    state = _state_from(link_resp)

    cb = await client.get(f"/api/v1/auth/oauth/github/callback?code=abc&state={state}")
    assert cb.status_code == 200
    assert "linked" in cb.json()["detail"]

    links = await client.get("/api/v1/auth/oauth/links")
    assert [link["provider"] for link in links.json()] == ["github"]


async def test_link_requires_authentication(client, monkeypatch):
    install_provider(monkeypatch, name="github", configured=("github",))
    resp = await _authorize(client, "github", "link")
    assert resp.status_code == 401


# --------------------------------------------------- provider/registry units
def test_google_authorization_url_uses_pkce():
    from app.services.oauth.providers import GoogleProvider

    url = GoogleProvider("cid", "sec").authorization_url(
        "state123", "http://cb", code_challenge="chal"
    )
    assert "accounts.google.com" in url
    assert "state=state123" in url
    assert "code_challenge=chal" in url
    assert "code_challenge_method=S256" in url
    assert "scope=openid" in url


def test_github_authorization_url_no_pkce():
    from app.services.oauth.providers import GitHubProvider

    url = GitHubProvider("cid", "sec").authorization_url("st", "http://cb")
    assert "github.com/login/oauth/authorize" in url
    assert "code_challenge" not in url
    assert "state=st" in url


def test_registry_resolves_configured_providers(monkeypatch):
    from app.core import config
    from app.services.oauth import registry

    monkeypatch.setattr(config.settings, "GOOGLE_CLIENT_ID", "id")
    monkeypatch.setattr(config.settings, "GOOGLE_CLIENT_SECRET", "sec")
    monkeypatch.setattr(config.settings, "GITHUB_CLIENT_ID", "")
    monkeypatch.setattr(config.settings, "GITHUB_CLIENT_SECRET", "")
    assert registry.get_provider("google") is not None
    assert registry.get_provider("github") is None
    assert registry.get_provider("unknown") is None
    assert registry.available_providers() == ["google"]
