"""OAuth proxy: this server is the MCP client's authorization server, and Entra ID does the login.

Why: MCP clients (Claude Code) send `resource=<MCP server URL>` (RFC 8707) to the authorization
server. Entra only accepts its own `api://...` identifier there and fails with AADSTS9010010.
So Claude Code talks OAuth to *this* server (discovery, dynamic client registration, PKCE),
and this server runs a second auth-code + PKCE flow against Entra as a public client.

    Claude Code --(DCR, /authorize, /token)--> this server --(authorize, token)--> Entra ID
                <------ Entra access token for api://<app>/mcp.access ----------

The access token handed to Claude Code is the real Entra token, so token validation is the same
as before (signature, issuer, tenant, audience, scope). Entra's refresh token stays on the server;
the client gets an opaque handle that this server redeems with Entra on refresh.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import time
from typing import Any

import httpx2
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .config import Settings
from .entra import EntraTokenVerifier, EntraValidator, Principal
from .store import Store

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS oauth_kv (
    kind       TEXT NOT NULL,      -- client | txn | code | refresh
    key        TEXT NOT NULL,
    data       TEXT NOT NULL,
    expires_at REAL,
    PRIMARY KEY (kind, key)
);
"""

TXN_TTL = 10 * 60      # user has 10 minutes to finish the Entra sign-in
CODE_TTL = 5 * 60      # client has 5 minutes to redeem our authorization code
REFRESH_TTL = 30 * 24 * 3600


class EntraProxyCode(AuthorizationCode):
    entra: dict[str, Any]  # Entra token response (kept server-side)


class EntraProxyRefresh(RefreshToken):
    entra_refresh_token: str


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class EntraProxyProvider:
    """OAuthAuthorizationServerProvider backed by Microsoft Entra ID."""

    def __init__(self, settings: Settings, store: Store, validator: EntraValidator):
        self.settings = settings
        self.store = store
        self.verifier = EntraTokenVerifier(validator)
        self.store._db.executescript(SCHEMA)
        # What we ask Entra for: the API scope, plus OIDC + refresh.
        self.entra_scope = f"{settings.full_scope} openid profile offline_access"

    # ---- tiny key/value persistence (survives container restarts) -------
    def _put(self, kind: str, key: str, data: dict[str, Any], ttl: float | None) -> None:
        expires = time.time() + ttl if ttl else None
        self.store._exec("INSERT OR REPLACE INTO oauth_kv (kind, key, data, expires_at) VALUES (?,?,?,?)",
                         (kind, key, json.dumps(data, default=str), expires))

    def _get(self, kind: str, key: str) -> dict[str, Any] | None:
        row = self.store._exec("SELECT data, expires_at FROM oauth_kv WHERE kind=? AND key=?", (kind, key)).fetchone()
        if not row:
            return None
        if row["expires_at"] and row["expires_at"] < time.time():
            self._del(kind, key)
            return None
        return json.loads(row["data"])

    def _del(self, kind: str, key: str) -> None:
        self.store._exec("DELETE FROM oauth_kv WHERE kind=? AND key=?", (kind, key))

    def is_proxy_state(self, state: str | None) -> bool:
        return bool(state) and self._get("txn", state) is not None

    # ---- dynamic client registration ------------------------------------
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self._get("client", client_id)
        return OAuthClientInformationFull.model_validate(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._put("client", client_info.client_id, client_info.model_dump(mode="json"), None)
        self.store.audit("oauth.client_registered", client_id=client_info.client_id,
                         client_name=client_info.client_name,
                         redirect_uris=[str(u) for u in client_info.redirect_uris or []])

    # ---- /authorize: hand the user to Entra --------------------------------
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        verifier, challenge = _pkce()
        txn = secrets.token_urlsafe(32)
        self._put("txn", txn, {
            "client_id": client.client_id,
            "client_state": params.state,
            "client_redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "client_code_challenge": params.code_challenge,
            "scopes": params.scopes or [self.settings.full_scope],
            "resource": params.resource,
            "entra_verifier": verifier,
        }, TXN_TTL)
        query = {
            "client_id": self.settings.client_id,
            "response_type": "code",
            "redirect_uri": self.settings.redirect_uri,
            "response_mode": "query",
            "scope": self.entra_scope,
            "state": txn,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        return construct_redirect_uri(self.settings.authorize_endpoint, **query)

    async def handle_entra_callback(self, request: Request) -> Response:
        """Entra redirected back for a proxied sign-in: redeem the code, then send the user back to the MCP client."""
        qp = request.query_params
        state = qp.get("state", "")
        txn = self._get("txn", state)
        self._del("txn", state)
        if not txn:
            return Response("Unknown or expired sign-in. Start again from your MCP client.", status_code=400)

        def back_to_client(**params: str | None) -> Response:
            return RedirectResponse(
                construct_redirect_uri(txn["client_redirect_uri"], state=txn["client_state"], **params), status_code=302)

        if "error" in qp:
            return back_to_client(error=qp.get("error"), error_description=qp.get("error_description"))

        async with httpx2.AsyncClient(timeout=20) as http:
            resp = await http.post(self.settings.token_endpoint, data={
                "client_id": self.settings.client_id,
                "grant_type": "authorization_code",
                "code": qp.get("code", ""),
                "redirect_uri": self.settings.redirect_uri,
                "code_verifier": txn["entra_verifier"],
                "scope": self.entra_scope,
            })
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code != 200 or "access_token" not in body:
            log.warning("Entra token exchange failed: %s", body or resp.text)
            return back_to_client(error="server_error",
                                  error_description=body.get("error_description", "Entra token exchange failed")[:300])

        token = await self.verifier.verify_token(body["access_token"])
        if token is None:
            return back_to_client(error="access_denied", error_description="Entra returned a token this server rejects")

        code = secrets.token_urlsafe(32)
        self._put("code", code, {
            "client_id": txn["client_id"],
            "client_redirect_uri": txn["client_redirect_uri"],
            "redirect_uri_provided_explicitly": txn["redirect_uri_provided_explicitly"],
            "client_code_challenge": txn["client_code_challenge"],
            "scopes": txn["scopes"],
            "resource": txn["resource"],
            "subject": token.subject,
            "entra": body,
        }, CODE_TTL)
        user = Principal.from_claims(token.claims or {})
        self.store.audit("oauth.signed_in", actor_oid=user.oid, actor_name=user.label, client_id=txn["client_id"])
        return back_to_client(code=code)

    # ---- /token: authorization code ---------------------------------------
    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        data = self._get("code", authorization_code)
        if not data or data["client_id"] != client.client_id:
            return None
        return EntraProxyCode(
            code=authorization_code,
            scopes=data["scopes"],
            expires_at=time.time() + CODE_TTL,
            client_id=data["client_id"],
            code_challenge=data["client_code_challenge"],
            redirect_uri=data["client_redirect_uri"],
            redirect_uri_provided_explicitly=data["redirect_uri_provided_explicitly"],
            resource=data["resource"],
            subject=data["subject"],
            entra=data["entra"],
        )

    async def exchange_authorization_code(self, client: OAuthClientInformationFull,
                                          authorization_code: EntraProxyCode) -> OAuthToken:
        self._del("code", authorization_code.code)  # single use
        return self._issue(client, authorization_code.entra, authorization_code.scopes, authorization_code.subject)

    def _issue(self, client: OAuthClientInformationFull, entra: dict[str, Any], scopes: list[str],
               subject: str | None) -> OAuthToken:
        handle = None
        if entra.get("refresh_token"):
            handle = secrets.token_urlsafe(32)
            self._put("refresh", handle, {"client_id": client.client_id, "scopes": scopes, "subject": subject,
                                          "entra_refresh_token": entra["refresh_token"]}, REFRESH_TTL)
        return OAuthToken(access_token=entra["access_token"], token_type="Bearer",
                          expires_in=int(entra.get("expires_in", 3600)), scope=" ".join(scopes), refresh_token=handle)

    # ---- /token: refresh ---------------------------------------------------
    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str):
        data = self._get("refresh", refresh_token)
        if not data or data["client_id"] != client.client_id:
            return None
        return EntraProxyRefresh(token=refresh_token, client_id=data["client_id"], scopes=data["scopes"],
                                 subject=data["subject"], entra_refresh_token=data["entra_refresh_token"])

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: EntraProxyRefresh,
                                     scopes: list[str]) -> OAuthToken:
        async with httpx2.AsyncClient(timeout=20) as http:
            resp = await http.post(self.settings.token_endpoint, data={
                "client_id": self.settings.client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token.entra_refresh_token,
                "scope": self.entra_scope,
            })
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        if resp.status_code != 200 or "access_token" not in body:
            raise TokenError(error="invalid_grant",
                             error_description=body.get("error_description", "Entra refused the refresh")[:300])
        self._del("refresh", refresh_token.token)  # rotate
        return self._issue(client, body, refresh_token.scopes, refresh_token.subject)

    # ---- resource server side ---------------------------------------------
    async def load_access_token(self, token: str) -> AccessToken | None:
        return await self.verifier.verify_token(token)

    async def revoke_token(self, token) -> None:
        if isinstance(token, RefreshToken):
            self._del("refresh", token.token)


__all__ = ["EntraProxyProvider", "AuthorizeError"]
