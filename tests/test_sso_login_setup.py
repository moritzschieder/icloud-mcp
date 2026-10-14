"""Owner sign-in through Cloudflare Access on the /login consent page and the /setup page (access_sso.py)."""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from icloud_mcp import access_sso, setup_page
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


async def test_setup_absent_without_sso(tmp_path, monkeypatch):
    app = _server(tmp_path, monkeypatch, sso=False)
    async with client_for(app) as c:
        r = await c.get("/setup", headers={"Cf-Access-Jwt-Assertion": token()})
    assert r.status_code == 404


async def test_setup_refuses_without_access_identity(sso_app):
    async with client_for(sso_app) as c:
        r = await c.get("/setup")
        p = await c.post("/setup", data={"password": "abcd-efgh-ijkl-mnop", "exp": "9999999999", "tok": "x"})
    assert r.status_code == 403 and p.status_code == 403


async def test_setup_saves_and_restarts(sso_app, monkeypatch):
    seen, timers = [], []
    async def fake_store(_s, raw, via):
        seen.append((raw, via))
        return None
    monkeypatch.setattr(setup_page, "check_and_store_app_password", fake_store)
    monkeypatch.setattr(setup_page.threading, "Timer", lambda delay, fn: type("T", (), {"start": lambda self: timers.append(delay)})())
    hdr = {"Cf-Access-Jwt-Assertion": token()}
    async with client_for(sso_app) as c:
        page = await c.get("/setup", headers=hdr)
        assert page.status_code == 200 and "me@icloud.com" in page.text
        exp = page.text.split('name="exp" value="', 1)[1].split('"', 1)[0]
        tok = page.text.split('name="tok" value="', 1)[1].split('"', 1)[0]
        r = await c.post("/setup", data={"password": "abcd-efgh-ijkl-mnop", "exp": exp, "tok": tok}, headers=hdr)
    assert r.status_code == 200 and "Saved" in r.text and "abcd" not in r.text
    assert seen == [("abcd-efgh-ijkl-mnop", "the /setup page")] and timers == [1.0]


async def test_setup_rejects_a_forged_form(sso_app, monkeypatch):
    called = []
    async def fake_store(*_a):
        called.append(1)
    monkeypatch.setattr(setup_page, "check_and_store_app_password", fake_store)
    async with client_for(sso_app) as c:
        r = await c.post("/setup", data={"password": "abcd-efgh-ijkl-mnop", "exp": "9999999999", "tok": "0" * 64},
                         headers={"Cf-Access-Jwt-Assertion": token()})
    assert r.status_code == 403 and called == []
