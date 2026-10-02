"""Owner sign-in to /outbox through a verified Cloudflare Access token (access_sso.py)."""
from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from icloud_mcp import access_sso
from icloud_mcp.config import Settings
from icloud_mcp.mail import MailService
from icloud_mcp.server import create_server

from test_outbox import client, env, queue_one  # noqa: F401  -- shared fixtures and helpers

TEAM = "example.cloudflareaccess.com"
AUD = "aud-tag-of-the-outbox-app"
OWNER = "owner@example.org"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJWKS:
    """Stands in for PyJWKClient: always hands out the real team key, whatever the token claims."""

    def __init__(self, *_a, **_kw):
        pass

    def get_signing_key_from_jwt(self, _token):
        return type("K", (), {"key": KEY.public_key()})()


def token(key=KEY, **over):
    now = int(time.time())
    claims = {"aud": [AUD], "iss": f"https://{TEAM}", "email": OWNER, "iat": now, "exp": now + 600, "sub": "x"}
    claims.update(over)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
def sso_web(env, monkeypatch):  # noqa: F811
    _s, fake, sent = env
    for k, v in dict(OWNER_ACCESS_TEAM_DOMAIN=f"https://{TEAM}/", OWNER_ACCESS_AUD=AUD, OWNER_ACCESS_EMAILS=f" {OWNER.upper()} ").items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(access_sso, "PyJWKClient", FakeJWKS)
    s = Settings.from_env()
    created, orig = [], MailService.__init__
    monkeypatch.setattr(MailService, "__init__", lambda self, st: (orig(self, st), created.append(self))[0])
    mcp, _provider = create_server(s)
    return mcp.streamable_http_app(host="0.0.0.0"), created[0], sent


async def test_valid_access_token_shows_the_queue_without_password(sso_web):
    app, mail, sent = sso_web
    queue_one(mail, subject="Quarterly report")
    async with client(app) as c:
        r = await c.get("/outbox", headers={"Cf-Access-Jwt-Assertion": token()})
    assert r.status_code == 200 and "Quarterly report" in r.text and "Owner password" not in r.text
    assert f"Signed in as {OWNER}" in r.text
    assert sent == []


@pytest.mark.parametrize("bad", [
    token(aud=["another-app"]),
    token(iss="https://evil.cloudflareaccess.com"),
    token(email="someone@example.org"),
    token(exp=int(time.time()) - 5),
    token(key=OTHER_KEY),
    "not-a-jwt",
])
async def test_invalid_tokens_fall_back_to_the_password_form(sso_web, bad):
    app, mail, sent = sso_web
    queue_one(mail, subject="Quarterly report")
    async with client(app) as c:
        r = await c.get("/outbox", headers={"Cf-Access-Jwt-Assertion": bad})
    assert r.status_code == 200 and "Owner password" in r.text and "Quarterly report" not in r.text


async def test_header_is_ignored_when_the_option_is_off(env, monkeypatch):  # noqa: F811
    s, fake, sent = env
    monkeypatch.setattr(access_sso, "PyJWKClient", FakeJWKS)
    created, orig = [], MailService.__init__
    monkeypatch.setattr(MailService, "__init__", lambda self, st: (orig(self, st), created.append(self))[0])
    mcp, _provider = create_server(s)
    app = mcp.streamable_http_app(host="0.0.0.0")
    queue_one(created[0], subject="Quarterly report")
    async with client(app) as c:
        r = await c.get("/outbox", headers={"Cf-Access-Jwt-Assertion": token()})
    assert "Owner password" in r.text and "Quarterly report" not in r.text


def test_option_needs_all_three_settings(env, monkeypatch):  # noqa: F811
    monkeypatch.setenv("OWNER_ACCESS_TEAM_DOMAIN", TEAM)
    monkeypatch.setenv("OWNER_ACCESS_AUD", AUD)
    assert access_sso.from_settings(Settings.from_env()) is None
    monkeypatch.setenv("OWNER_ACCESS_EMAILS", OWNER)
    assert access_sso.from_settings(Settings.from_env()) is not None
