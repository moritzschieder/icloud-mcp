"""Owner sign-in through Cloudflare Access on the /login consent page (access_sso.py)."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from icloud_mcp import access_sso
from icloud_mcp.config import Settings
from icloud_mcp.server import create_server

from test_access_sso import AUD, OWNER, TEAM, FakeJWKS, token
from test_oauth_flow import BASE, PASSWORD, REDIRECT, client_for, pkce, register


def _server(tmp_path, monkeypatch, sso: bool = True):
    env = dict(ICLOUD_USERNAME="me@icloud.com", ICLOUD_APP_PASSWORD="aaaa-bbbb-cccc-dddd", MCP_PUBLIC_URL=BASE,
               MCP_OWNER_PASSWORD=PASSWORD, DATA_DIR=str(tmp_path))
    if sso:
        env.update(OWNER_ACCESS_TEAM_DOMAIN=TEAM, OWNER_ACCESS_AUD=AUD, OWNER_ACCESS_EMAILS=OWNER)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(access_sso, "PyJWKClient", FakeJWKS)
    mcp, provider = create_server(Settings.from_env())
    return mcp.streamable_http_app(host="0.0.0.0")


@pytest.fixture
def sso_app(tmp_path, monkeypatch):
    return _server(tmp_path, monkeypatch)


async def _pending(c):
    cid = (await register(c)).json()["client_id"]
    _verifier, challenge = pkce()
    r = await c.get("/authorize", params={"response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
                                          "code_challenge": challenge, "code_challenge_method": "S256", "state": "s", "scope": "icloud"})
    return parse_qs(urlsplit(r.headers["location"]).query)["p"][0]


def _sso_field(page: str) -> str:
    return page.split('name="sso" value="', 1)[1].split('"', 1)[0]


async def test_login_with_access_identity_needs_no_password(sso_app):
    async with client_for(sso_app) as c:
        pid = await _pending(c)
        page = await c.get(f"/login?p={pid}", headers={"Cf-Access-Jwt-Assertion": token()})
        assert page.status_code == 200 and f"Signed in as <b>{OWNER}</b>" in page.text and "Owner password" not in page.text
        r = await c.post("/login", data={"p": pid, "sso": _sso_field(page.text), "action": "approve"},
                         headers={"Cf-Access-Jwt-Assertion": token()})
    assert r.status_code == 302 and r.headers["location"].startswith(REDIRECT) and "code=" in r.headers["location"]


async def test_login_sso_approval_needs_the_access_header_on_the_post(sso_app):
    async with client_for(sso_app) as c:
        pid = await _pending(c)
        page = await c.get(f"/login?p={pid}", headers={"Cf-Access-Jwt-Assertion": token()})
        r = await c.post("/login", data={"p": pid, "sso": _sso_field(page.text), "action": "approve"})
    assert r.status_code == 403 and "code=" not in r.headers.get("location", "")


async def test_login_sso_token_is_bound_to_its_request(sso_app):
    async with client_for(sso_app) as c:
        pid_a, pid_b = await _pending(c), await _pending(c)
        page_a = await c.get(f"/login?p={pid_a}", headers={"Cf-Access-Jwt-Assertion": token()})
        r = await c.post("/login", data={"p": pid_b, "sso": _sso_field(page_a.text), "action": "approve"},
                         headers={"Cf-Access-Jwt-Assertion": token()})
    assert r.status_code == 403


async def test_login_other_identity_gets_the_password_form(sso_app):
    async with client_for(sso_app) as c:
        pid = await _pending(c)
        page = await c.get(f"/login?p={pid}", headers={"Cf-Access-Jwt-Assertion": token(email="someone@example.org")})
    assert "Owner password" in page.text and 'name="sso"' not in page.text


async def test_password_still_works_with_sso_on(sso_app):
    async with client_for(sso_app) as c:
        pid = await _pending(c)
        r = await c.post("/login", data={"p": pid, "password": PASSWORD, "action": "approve"})
    assert r.status_code == 302 and "code=" in r.headers["location"]


async def test_no_setup_page_even_with_sso(sso_app):
    # The app password stays in .env (1Password); no web page may change it.
    async with client_for(sso_app) as c:
        r = await c.get("/setup", headers={"Cf-Access-Jwt-Assertion": token()})
        p = await c.post("/setup", data={"password": "abcd-efgh-ijkl-mnop"}, headers={"Cf-Access-Jwt-Assertion": token()})
    assert r.status_code == 404 and p.status_code in (404, 405)


async def test_pages_tell_cloudflare_not_to_rewrite_them(sso_app):
    # Cloudflare's email obfuscation would turn recipients into "[email protected]"; no-transform switches it off per response.
    async with client_for(sso_app) as c:
        pid = await _pending(c)
        login = await c.get(f"/login?p={pid}", headers={"Cf-Access-Jwt-Assertion": token()})
        outbox = await c.get("/outbox", headers={"Cf-Access-Jwt-Assertion": token()})
    assert "no-transform" in login.headers["cache-control"] and "no-transform" in outbox.headers["cache-control"]
