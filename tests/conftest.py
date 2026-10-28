"""Test fixtures: a mock Entra ID (JWKS, authorize, token endpoints) and the app on a real port."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

from app.config import Settings
from app.policy import parse_policy
from app.server import build

TENANT = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
APP_ID_URI = f"api://{CLIENT_ID}"
AZURE_CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

ALICE = {"oid": "aaaaaaaa-0000-0000-0000-000000000001", "name": "Alice Admin", "preferred_username": "alice@contoso.test"}
BOB = {"oid": "bbbbbbbb-0000-0000-0000-000000000002", "name": "Bob Approver", "preferred_username": "bob@contoso.test"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve(app, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError("server did not start")


@dataclass
class MockEntra:
    """Just enough of Entra ID for the tests: signs tokens, serves JWKS, runs auth-code + PKCE."""

    port: int
    key: rsa.RSAPrivateKey = field(default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048))
    kid: str = "test-key"
    signed_in_as: dict = field(default_factory=lambda: dict(ALICE))  # who "types their password" in the browser
    codes: dict = field(default_factory=dict)
    refresh_tokens: dict = field(default_factory=dict)
    last_authorize: dict = field(default_factory=dict)

    @property
    def authority(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def v2_issuer(self) -> str:
        return f"{self.authority}/{TENANT}/v2.0"

    def sign(self, claims: dict, key=None) -> str:
        return jwt.encode(claims, key or self.key, algorithm="RS256", headers={"kid": self.kid})

    def access_token(self, user: dict = ALICE, *, version: str = "1.0", scp: str = "mcp.access",
                     aud: str | None = None, tid: str = TENANT, exp_in: int = 3600, key=None) -> str:
        now = int(time.time())
        claims = {"tid": tid, "oid": user["oid"], "name": user["name"], "scp": scp, "iat": now, "nbf": now,
                  "exp": now + exp_in, "ver": version}
        if version == "1.0":  # what Azure CLI gets by default
            claims |= {"iss": f"https://sts.windows.net/{tid}/", "aud": aud or APP_ID_URI, "appid": AZURE_CLI,
                       "unique_name": user["preferred_username"]}
        else:
            claims |= {"iss": f"{self.authority}/{tid}/v2.0", "aud": aud or CLIENT_ID, "azp": AZURE_CLI,
                       "preferred_username": user["preferred_username"]}
        return self.sign(claims, key)

    def _token_response(self, user: dict, nonce: str | None, scope: str) -> dict:
        now = int(time.time())
        body = {"token_type": "Bearer", "expires_in": 3600}
        id_claims = {"iss": self.v2_issuer, "aud": CLIENT_ID, "tid": TENANT, "iat": now, "nbf": now, "exp": now + 3600, **user}
        if nonce:
            id_claims["nonce"] = nonce
        body["id_token"] = self.sign(id_claims)
        if f"{APP_ID_URI}/mcp.access" in scope:
            body["access_token"] = self.access_token(user, version="2.0")
            body["scope"] = f"{APP_ID_URI}/mcp.access"
        if "offline_access" in scope:
            rt = secrets.token_urlsafe(16)
            self.refresh_tokens[rt] = user
            body["refresh_token"] = rt
        return body

    def app(self) -> Starlette:
        async def jwks(request: Request):
            jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
            return JSONResponse({"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]})

        async def authorize(request: Request):
            q = dict(request.query_params)
            self.last_authorize = q
            code = secrets.token_urlsafe(16)
            self.codes[code] = {"q": q, "user": dict(self.signed_in_as)}
            return RedirectResponse(f"{q['redirect_uri']}?{urlencode({'code': code, 'state': q['state']})}", 302)

        async def token(request: Request):
            form = dict(await request.form())
            if form.get("grant_type") == "refresh_token":
                user = self.refresh_tokens.pop(form.get("refresh_token", ""), None)
                if not user:
                    return JSONResponse({"error": "invalid_grant", "error_description": "bad refresh token"}, 400)
                return JSONResponse(self._token_response(user, None, form.get("scope", "")))
            entry = self.codes.pop(form.get("code", ""), None)
            if not entry:
                return JSONResponse({"error": "invalid_grant", "error_description": "bad code"}, 400)
            q, user = entry["q"], entry["user"]
            if "resource" in q:  # what real Entra does when resource and scope disagree
                return JSONResponse({"error": "invalid_target", "error_description": "AADSTS9010010"}, 400)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
            if challenge != q["code_challenge"] or form["redirect_uri"] != q["redirect_uri"] or form["client_id"] != q["client_id"]:
                return JSONResponse({"error": "invalid_grant", "error_description": "PKCE/redirect mismatch"}, 400)
            return JSONResponse(self._token_response(user, q.get("nonce"), q.get("scope", "")))

        return Starlette(routes=[
            Route(f"/{TENANT}/discovery/v2.0/keys", jwks),
            Route(f"/{TENANT}/oauth2/v2.0/authorize", authorize),
            Route(f"/{TENANT}/oauth2/v2.0/token", token, methods=["POST"]),
        ])


@pytest.fixture(scope="session")
def entra() -> MockEntra:
    mock = MockEntra(port=free_port())
    serve(mock.app(), mock.port)
    return mock


POLICY = {
    "approval_mode": "self",
    "reauth_minutes": 10,
    "tools": {
        "restart_service": {"jit_when": {"env": ["prod"]}, "ttl_minutes": 15, "bind_args": ["service", "env"]},
        "scale_service": {"jit_when": {"env": ["prod"]}, "ttl_minutes": 10, "bind_args": ["service", "env", "replicas"]},
        "rotate_secret": {"jit_when": "always", "ttl_minutes": 5, "bind_args": ["service", "env"], "single_use": True},
    },
}


@dataclass
class Running:
    base: str
    demo: object
    entra: MockEntra


def start_app(entra: MockEntra, tmp_path, policy: dict) -> Running:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    settings = Settings(tenant_id=TENANT, client_id=CLIENT_ID, app_id_uri=APP_ID_URI, public_base_url=base,
                        authority=entra.authority, db_path=str(tmp_path / "jit.db"), session_secret="test-secret")
    demo = build(settings, parse_policy(policy))
    serve(demo.app, port)
    return Running(base=base, demo=demo, entra=entra)


@pytest.fixture
def server(entra, tmp_path) -> Running:
    entra.signed_in_as = dict(ALICE)
    return start_app(entra, tmp_path, POLICY)


@pytest.fixture
def two_person_server(entra, tmp_path) -> Running:
    entra.signed_in_as = dict(ALICE)
    return start_app(entra, tmp_path, {**POLICY, "approval_mode": "two_person"})


@pytest.fixture
def anyio_backend():
    return "asyncio"
