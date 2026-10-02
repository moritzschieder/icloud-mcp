"""Optional owner sign-in through Cloudflare Access for the /outbox page.

When the server sits behind a Cloudflare Access application that already authenticates the owner (for example with an
OIDC identity provider and a passkey), asking for the owner password again on /outbox is a second login for the same
person. With OWNER_ACCESS_TEAM_DOMAIN, OWNER_ACCESS_AUD and OWNER_ACCESS_EMAILS set, the page accepts the identity that
Access forwards instead.

What is trusted is the signed `Cf-Access-Jwt-Assertion` header, never a plain email header: the token's RS256 signature
is checked against the team's published keys, its audience must be this Access application, its issuer the team domain,
it must be unexpired, and its email must be one of the configured owner identities. A request that reaches the origin
without passing Access carries no valid token and falls back to the password form. The password keeps working.

The team keys come from `https://<team>/cdn-cgi/access/certs`. A host whose container may not reach the internet sets
OWNER_ACCESS_CERTS_FILE instead: something outside the container refreshes that file, and it is re-read when it changes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import jwt
from jwt import PyJWKClient, PyJWKSet

log = logging.getLogger(__name__)

HEADER = "cf-access-jwt-assertion"
FETCH_TIMEOUT = 5  # seconds; a key fetch that hangs must not hold the page, the password form is the fallback


class FileJWKS:
    """The team key set from a local JSON file (the body of /cdn-cgi/access/certs), re-read when the file changes."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._mtime = -1.0
        self._keys: dict[str, Any] = {}

    def _load(self) -> None:
        mtime = os.stat(self.path).st_mtime
        if mtime != self._mtime:
            with open(self.path, encoding="utf-8") as f:
                keyset = PyJWKSet.from_dict(json.load(f))
            self._keys = {k.key_id: k for k in keyset.keys}
            self._mtime = mtime

    def get_signing_key_from_jwt(self, token: str) -> Any:
        self._load()
        kid = jwt.get_unverified_header(token).get("kid")
        if kid not in self._keys:
            raise jwt.PyJWKClientError(f"no key with this kid in {self.path}")
        return self._keys[kid]


class AccessOwnerVerifier:
    def __init__(self, team_domain: str, aud: str, emails: tuple[str, ...], jwks_client: Any = None) -> None:
        self.issuer = f"https://{team_domain}"
        self.aud = aud
        self.emails = frozenset(e.lower() for e in emails)
        # PyJWKClient caches the key set and refetches on an unknown key id (key rotation).
        self._jwks = jwks_client or PyJWKClient(f"{self.issuer}/cdn-cgi/access/certs", cache_keys=True, lifespan=3600,
                                                timeout=FETCH_TIMEOUT)

    def _verify(self, token: str) -> str | None:
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.aud, issuer=self.issuer,
                                options={"require": ["exp", "iat", "aud", "iss"]})
        except Exception as e:  # noqa: BLE001  -- any failure means "not signed in", the password form stays
            log.warning("Rejected Cloudflare Access token on /outbox: %s", type(e).__name__)
            return None
        email = str(claims.get("email", "")).lower()
        if email not in self.emails:
            log.warning("Cloudflare Access identity is not an owner identity; showing the password form")
            return None
        return email

    async def owner_email(self, headers: Any) -> str | None:
        """The owner identity Access vouches for on this request, or None."""
        token = headers.get(HEADER, "")
        if not token:
            return None
        return await asyncio.to_thread(self._verify, token)


def from_settings(settings: Any) -> AccessOwnerVerifier | None:
    if settings.owner_access_team and settings.owner_access_aud and settings.owner_access_emails:
        jwks = FileJWKS(settings.owner_access_certs_file) if settings.owner_access_certs_file else None
        return AccessOwnerVerifier(settings.owner_access_team, settings.owner_access_aud, settings.owner_access_emails, jwks)
    return None
