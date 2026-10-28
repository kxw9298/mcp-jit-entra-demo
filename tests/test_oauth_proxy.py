"""What Claude Code does on /mcp → Authenticate: discovery, DCR, PKCE, browser sign-in at Entra, token, refresh."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest

from .conftest import ALICE, APP_ID_URI, CLIENT_ID
from .test_e2e import Agent

pytestmark = pytest.mark.anyio

CLIENT_REDIRECT = "http://localhost:53682/callback"  # Claude Code's loopback listener


async def sign_in_like_claude_code(server, http: httpx2.AsyncClient) -> dict:
    # 1. Unauthenticated call → 401 pointing at protected-resource metadata.
    r = await http.post(f"{server.base}/mcp", json={})
    assert r.status_code == 401
    prm = (await http.get(f"{server.base}/.well-known/oauth-protected-resource/mcp")).json()
    issuer = prm["authorization_servers"][0]
    scope = prm["scopes_supported"][0]
    assert scope == f"{APP_ID_URI}/mcp.access"

    # 2. Authorization server metadata (this server).
    meta = (await http.get(f"{issuer}/.well-known/oauth-authorization-server")).json()
    assert meta["code_challenge_methods_supported"] == ["S256"]

    # 3. Dynamic client registration.
    reg = await http.post(meta["registration_endpoint"], json={
        "client_name": "Claude Code (test)", "redirect_uris": [CLIENT_REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none", "scope": scope,
    })
    assert reg.status_code == 201, reg.text
    client_id = reg.json()["client_id"]

    # 4. Authorize with PKCE and the RFC 8707 resource the MCP spec requires.
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(8)
    r = await http.get(meta["authorization_endpoint"], params={
        "response_type": "code", "client_id": client_id, "redirect_uri": CLIENT_REDIRECT, "scope": scope,
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        "resource": f"{server.base}/mcp",
    })
    assert r.status_code == 302
    entra_url = r.headers["location"]
    assert entra_url.startswith(server.entra.authority)          # browser goes to Entra
    q = parse_qs(urlparse(entra_url).query)
    assert "resource" not in q                                    # the AADSTS9010010 trigger is gone
    assert f"{APP_ID_URI}/mcp.access" in q["scope"][0]

    # 5. Browser: Entra sign-in → our callback → back to Claude Code's loopback with a code.
    r = await http.get(entra_url)                                  # mock Entra redirects to our callback
    assert r.status_code == 302
    r = await http.get(r.headers["location"])                     # our callback redeems Entra's code
    assert r.status_code == 302, r.text
    back = urlparse(r.headers["location"])
    assert f"{back.scheme}://{back.netloc}{back.path}" == CLIENT_REDIRECT
    params = parse_qs(back.query)
    assert params["state"] == [state]

    # 6. Token exchange with the PKCE verifier.
    tok = await http.post(meta["token_endpoint"], data={
        "grant_type": "authorization_code", "code": params["code"][0], "redirect_uri": CLIENT_REDIRECT,
        "client_id": client_id, "code_verifier": verifier, "resource": f"{server.base}/mcp",
    })
    assert tok.status_code == 200, tok.text
    body = tok.json()
    assert body["refresh_token"] and body["access_token"]
    return {"client_id": client_id, "meta": meta, **body}


async def test_claude_code_style_sign_in_then_tools_work(server):
    server.entra.signed_in_as = dict(ALICE)
    async with httpx2.AsyncClient(timeout=30) as http:
        tokens = await sign_in_like_claude_code(server, http)

        # The token works for MCP, as Alice.
        is_error, text = await Agent(server.base, tokens["access_token"]).call("whoami")
        assert not is_error, text
        assert json.loads(text)["object_id"] == ALICE["oid"]

        # JIT still applies on top of OAuth.
        is_error, text = await Agent(server.base, tokens["access_token"]).call(
            "restart_service", {"service": "payments", "env": "prod"})
        assert is_error and "JIT approval required" in text

        # Refresh: opaque handle → new Entra token, handle rotated.
        r = await http.post(tokens["meta"]["token_endpoint"], data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": tokens["client_id"]})
        assert r.status_code == 200, r.text
        refreshed = r.json()
        assert refreshed["refresh_token"] != tokens["refresh_token"]
        assert not (await Agent(server.base, refreshed["access_token"]).call("whoami"))[0]

        # Old refresh handle is single use.
        r = await http.post(tokens["meta"]["token_endpoint"], data={
            "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": tokens["client_id"]})
        assert r.status_code == 400


async def test_code_needs_the_right_pkce_verifier(server):
    async with httpx2.AsyncClient(timeout=30) as http:
        r = await http.post(f"{server.base}/register", json={
            "redirect_uris": [CLIENT_REDIRECT], "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"], "scope": f"{APP_ID_URI}/mcp.access"})
        client_id = r.json()["client_id"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        r = await http.get(f"{server.base}/authorize", params={
            "response_type": "code", "client_id": client_id, "redirect_uri": CLIENT_REDIRECT,
            "scope": f"{APP_ID_URI}/mcp.access", "state": "s", "code_challenge": challenge, "code_challenge_method": "S256"})
        r = await http.get(r.headers["location"])
        r = await http.get(r.headers["location"])
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        bad = await http.post(f"{server.base}/token", data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": CLIENT_REDIRECT,
            "client_id": client_id, "code_verifier": "wrong-" + verifier})
        assert bad.status_code == 400
