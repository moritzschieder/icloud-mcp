"""/setup: the owner enters or replaces the iCloud app-specific password in the browser.

Only served when owner sign-in through Cloudflare Access is configured (access_sso.py), and only to a request that
carries a verified owner identity: there is no password fallback, because the page exists so that the owner does not
have to hand the app-specific password to anyone else (an admin, a chat, an agent). The value is proven against iCloud
Mail before it is stored in DATA_DIR/overrides.json, then the server exits so the container restart policy brings it
back with the new password. Nothing about the value is logged or echoed back.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import logging
import os
import secrets
import threading
import time
from typing import Any, Callable

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from . import access_sso
from .admin import check_and_store_app_password
from .auth import _HEADERS
from .config import Settings

log = logging.getLogger(__name__)

TOKEN_TTL = 600  # seconds a form stays valid

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>iCloud connector setup</title>
<style>
:root{{color-scheme:light dark;--bg:#f5f5f7;--card:#fff;--text:#1d1d1f;--muted:#666;--line:#bbb;--accent:#0071e3;--err:#c00;--ok:#1a7f37;--shadow:#0002}}
@media (prefers-color-scheme:dark){{:root{{--bg:#000;--card:#1c1c1e;--text:#f5f5f7;--muted:#98989d;--line:#48484a;--accent:#0a84ff;--err:#ff6961;--ok:#3fb950;--shadow:#0000}}}}
body{{font:16px/1.5 -apple-system,system-ui,sans-serif;background:var(--bg);color:var(--text);margin:0;display:grid;place-items:center;min-height:100vh}}
main{{background:var(--card);padding:2rem;border-radius:14px;max-width:26rem;width:calc(100% - 2rem);box-shadow:0 2px 20px var(--shadow)}}
h1{{font-size:1.25rem;margin:0 0 .5rem}} p{{margin:.5rem 0}} .err{{color:var(--err)}} .ok{{color:var(--ok)}} .muted{{color:var(--muted);font-size:.9rem}}
input[type=password]{{width:100%;box-sizing:border-box;padding:.7rem;font-size:1rem;border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;margin:.5rem 0 1rem}}
button{{padding:.7rem 1.2rem;font-size:1rem;border-radius:8px;border:0;cursor:pointer;background:var(--accent);color:#fff}}
</style></head><body><main><h1>iCloud connector setup</h1>{body}</main></body></html>"""


def _html(body: str, status: int = 200) -> Response:
    return HTMLResponse(_PAGE.format(body=body), status_code=status, headers=_HEADERS)


def register_setup_routes(mcp: Any, settings: Settings, *, exit_fn: Callable[[], None] | None = None) -> None:
    access = access_sso.from_settings(settings)
    if access is None:
        return  # without a verified owner identity there is no safe way to offer this page
    key = secrets.token_bytes(32)  # per-process: a form issued before a restart simply asks again
    exit_fn = exit_fn or (lambda: os._exit(0))  # the container restart policy starts the server again

    def _tok(who: str, exp: int) -> str:
        return hmac.new(key, f"setup|{who}|{exp}".encode(), hashlib.sha256).hexdigest()

    def _form(who: str, error: str = "", status: int = 200) -> Response:
        exp = int(time.time()) + TOKEN_TTL
        return _html(f"""<p class="muted">Signed in as <b>{html.escape(who)}</b> through Cloudflare Access.</p>
<p>Account: <b>{html.escape(settings.username)}</b></p>
<p>Enter an app-specific password for this Apple Account (account.apple.com, Sign-In and Security, App-Specific
Passwords). It is checked with iCloud Mail before anything is saved.</p>{f'<p class="err">{html.escape(error)}</p>' if error else ''}
<form method="post" action="/setup"><input type="hidden" name="exp" value="{exp}"><input type="hidden" name="tok" value="{_tok(who, exp)}">
<label for="pw">App-specific password</label>
<input id="pw" type="password" name="password" autocomplete="off" placeholder="abcd-efgh-ijkl-mnop" autofocus required>
<button type="submit">Check and save</button></form>""", status)

    @mcp.custom_route("/setup", methods=["GET"])
    async def setup_get(request: Request) -> Response:
        who = await access.owner_email(request.headers)
        if not who:
            return _html('<p class="err">This page is only available after signing in through Cloudflare Access.</p>', 403)
        return _form(who)

    @mcp.custom_route("/setup", methods=["POST"])
    async def setup_post(request: Request) -> Response:
        who = await access.owner_email(request.headers)
        if not who:
            return _html('<p class="err">This page is only available after signing in through Cloudflare Access.</p>', 403)
        form = await request.form()
        try:
            exp = int(str(form.get("exp", "0")))
        except ValueError:
            exp = 0
        if exp < time.time() or not hmac.compare_digest(str(form.get("tok", "")).encode(), _tok(who, exp).encode()):
            log.warning("Rejected a /setup submission with an expired or invalid token")
            return _form(who, "This form has expired. Enter the password again.", 403)
        if problem := await check_and_store_app_password(settings, str(form.get("password", "")), "the /setup page"):
            return _form(who, problem, 400)
        log.warning("Owner replaced the iCloud app-specific password on /setup; restarting")
        threading.Timer(1.0, exit_fn).start()  # after the response has gone out
        return _html('<p class="ok">Saved. The connector restarts with the new password and is back in about 30 seconds.</p>'
                     '<p class="muted">You can close this page.</p>')
