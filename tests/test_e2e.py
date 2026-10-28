"""End-to-end: real HTTP server, MCP client over Streamable HTTP, approval page via mock Entra sign-in."""

from __future__ import annotations

import json
import re

import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .conftest import ALICE, APP_ID_URI, BOB, CLIENT_ID, TENANT

pytestmark = pytest.mark.anyio


class Agent:
    """An MCP client session acting for one user (what Claude Code does)."""

    def __init__(self, base: str, token: str):
        self.base, self.token = base, token

    async def call(self, tool: str, args: dict | None = None):
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {self.token}"}, timeout=30) as http:
            async with streamable_http_client(f"{self.base}/mcp", http_client=http) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool, args or {})
        text = result.content[0].text if result.content else ""
        return result.is_error, text

    async def tools(self) -> list[str]:
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {self.token}"}, timeout=30) as http:
            async with streamable_http_client(f"{self.base}/mcp", http_client=http) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return [t.name for t in (await session.list_tools()).tools]


class Browser:
    """A browser session on the approval page; signs in through the mock Entra."""

    def __init__(self, base: str):
        self.http = httpx2.AsyncClient(base_url=base, follow_redirects=True, timeout=30)

    async def open(self, path: str) -> httpx2.Response:
        return await self.http.get(path)

    async def post(self, path: str, page: httpx2.Response, **extra) -> httpx2.Response:
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        return await self.http.post(path, data={"csrf": csrf, **extra})

    async def aclose(self):
        await self.http.aclose()


def request_id_from(text: str) -> str:
    return re.search(r"JIT-[0-9A-F]{6}", text).group(0)


# --------------------------------------------------------------------------- OAuth / resource server


async def test_no_token_gets_401_with_resource_metadata(server):
    async with httpx2.AsyncClient() as http:
        r = await http.post(f"{server.base}/mcp", json={})
        assert r.status_code == 401
        assert f'resource_metadata="{server.base}/.well-known/oauth-protected-resource/mcp"' in r.headers["www-authenticate"]

        prm = (await http.get(f"{server.base}/.well-known/oauth-protected-resource/mcp")).json()
        assert prm["resource"] == f"{server.base}/mcp"
        assert prm["authorization_servers"] == [server.base]  # this server proxies sign-in to Entra
        assert prm["scopes_supported"] == [f"{APP_ID_URI}/mcp.access"]


@pytest.mark.parametrize("case", ["wrong_aud", "other_tenant", "expired", "bad_signature"])
async def test_bad_tokens_are_rejected(server, case):
    e = server.entra
    token = {
        "wrong_aud": lambda: e.access_token(aud="api://some-other-api"),
        "other_tenant": lambda: e.access_token(tid="99999999-9999-9999-9999-999999999999"),
        "expired": lambda: e.access_token(exp_in=-600),
        "bad_signature": lambda: e.access_token(key=rsa.generate_private_key(public_exponent=65537, key_size=2048)),
    }[case]()
    async with httpx2.AsyncClient() as http:
        r = await http.post(f"{server.base}/mcp", json={}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


async def test_missing_scope_gets_403_insufficient_scope(server):
    token = server.entra.access_token(scp="User.Read")
    async with httpx2.AsyncClient() as http:
        r = await http.post(f"{server.base}/mcp", json={}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]


@pytest.mark.parametrize("version", ["1.0", "2.0"])
async def test_v1_and_v2_tokens_work(server, version):
    is_error, text = await Agent(server.base, server.entra.access_token(ALICE, version=version)).call("whoami")
    assert not is_error, text
    who = json.loads(text)
    assert who["object_id"] == ALICE["oid"]
    assert who["username"] == ALICE["preferred_username"]
    assert who["scopes"] == [f"{APP_ID_URI}/mcp.access"]


async def test_tools_listed(server):
    names = await Agent(server.base, server.entra.access_token()).tools()
    assert {"whoami", "list_services", "restart_service", "rotate_secret", "check_jit_request"} <= set(names)


# --------------------------------------------------------------------------- JIT flow


async def test_full_jit_flow_self_approval(server):
    alice = Agent(server.base, server.entra.access_token(ALICE))

    # Read-only and dev changes need no approval.
    assert not (await alice.call("list_services", {"env": "prod"}))[0]
    is_error, text = await alice.call("restart_service", {"service": "payments", "env": "dev"})
    assert not is_error and "restarted" in text

    # Prod restart: blocked, request created, nothing changed.
    is_error, text = await alice.call("restart_service", {"service": "payments", "env": "prod", "reason": "INC-42 memory leak"})
    assert is_error and "JIT approval required" in text and "Nothing was changed" in text
    rid = request_id_from(text)
    assert f"{server.base}/jit/{rid}" in text
    status = json.loads((await alice.call("get_service_status", {"service": "payments", "env": "prod"}))[1])
    assert status["last_actor"] is None

    # Retrying before approval reuses the same request instead of piling up new ones.
    _, again = await alice.call("restart_service", {"service": "payments", "env": "prod"})
    assert request_id_from(again) == rid
    assert json.loads((await alice.call("check_jit_request", {"request_id": rid}))[1])["status"] == "pending"

    # Alice opens the link, signs in with Entra (mock), sees the details and approves.
    browser = Browser(server.base)
    page = await browser.open(f"/jit/{rid}")
    assert server.entra.last_authorize["code_challenge_method"] == "S256"
    assert server.entra.last_authorize["client_id"] == CLIENT_ID
    assert page.status_code == 200 and rid in page.text and "INC-42 memory leak" in page.text
    assert 'service=&#34;payments&#34;' in page.text or "payments" in page.text
    page = await browser.post(f"/jit/{rid}/approve", page)
    assert "Approved." in page.text

    # The agent retries and it works; the grant is attributed to Alice.
    is_error, text = await alice.call("restart_service", {"service": "payments", "env": "prod"})
    assert not is_error, text
    assert json.loads(text)["jit_request"] == rid
    status = json.loads((await alice.call("get_service_status", {"service": "payments", "env": "prod"}))[1])
    assert status["last_actor"].startswith("Alice Admin")

    # The grant is pinned to its arguments: a different service needs its own approval.
    is_error, text = await alice.call("restart_service", {"service": "orders", "env": "prod"})
    assert is_error and request_id_from(text) != rid

    # Bob can't ride on Alice's grant.
    bob = Agent(server.base, server.entra.access_token(BOB))
    is_error, text = await bob.call("restart_service", {"service": "payments", "env": "prod"})
    assert is_error and "JIT approval required" in text

    # Revoke from the approval page: access ends immediately.
    page = await browser.open(f"/jit/{rid}")
    page = await browser.post(f"/jit/{rid}/revoke", page)
    assert "Revoked." in page.text
    is_error, text = await alice.call("restart_service", {"service": "payments", "env": "prod"})
    assert is_error and "JIT approval required" in text

    # Everything landed in the audit log.
    events = [e["event"] for e in server.demo.store.recent_audit(100)]
    for expected in ("jit.request_created", "web.signed_in", "jit.approved", "jit.grant_used", "tool.executed", "jit.revoked"):
        assert expected in events
    await browser.aclose()


async def test_single_use_grant(server):
    alice = Agent(server.base, server.entra.access_token(ALICE))
    _, text = await alice.call("rotate_secret", {"service": "orders", "env": "dev"})
    rid = request_id_from(text)
    browser = Browser(server.base)
    page = await browser.open(f"/jit/{rid}")
    await browser.post(f"/jit/{rid}/approve", page)

    is_error, text = await alice.call("rotate_secret", {"service": "orders", "env": "dev"})
    assert not is_error and "v2" in text
    is_error, text = await alice.call("rotate_secret", {"service": "orders", "env": "dev"})
    assert is_error and request_id_from(text) != rid  # consumed: needs a new approval
    assert server.demo.store.get_request(rid).status == "used"
    await browser.aclose()


async def test_deny(server):
    alice = Agent(server.base, server.entra.access_token(ALICE))
    _, text = await alice.call("scale_service", {"service": "inventory", "env": "prod", "replicas": 6})
    rid = request_id_from(text)
    browser = Browser(server.base)
    page = await browser.open(f"/jit/{rid}")
    page = await browser.post(f"/jit/{rid}/deny", page)
    assert "Denied." in page.text
    assert json.loads((await alice.call("check_jit_request", {"request_id": rid}))[1])["status"] == "denied"
    await browser.aclose()


async def test_two_person_rule(two_person_server):
    srv = two_person_server
    alice = Agent(srv.base, srv.entra.access_token(ALICE))
    _, text = await alice.call("restart_service", {"service": "payments", "env": "prod"})
    rid = request_id_from(text)

    # Alice signs in and tries to approve her own request: blocked.
    srv.entra.signed_in_as = dict(ALICE)
    alice_browser = Browser(srv.base)
    page = await alice_browser.open(f"/jit/{rid}")
    assert "can&#39;t approve your own request" in page.text or "can't approve your own request" in page.text
    assert f'action="/jit/{rid}/approve"' not in page.text
    # Even posting the form directly is refused.
    r = await alice_browser.post(f"/jit/{rid}/approve", page)
    assert r.status_code == 403
    assert srv.demo.store.get_request(rid).status == "pending"

    # Bob signs in on his own browser and approves.
    srv.entra.signed_in_as = dict(BOB)
    bob_browser = Browser(srv.base)
    page = await bob_browser.open(f"/jit/{rid}")
    page = await bob_browser.post(f"/jit/{rid}/approve", page)
    assert "Approved." in page.text
    assert srv.demo.store.get_request(rid).decided_by_oid == BOB["oid"]

    is_error, text = await alice.call("restart_service", {"service": "payments", "env": "prod"})
    assert not is_error, text
    await alice_browser.aclose()
    await bob_browser.aclose()


async def test_approval_page_requires_sign_in_and_csrf(server):
    alice = Agent(server.base, server.entra.access_token(ALICE))
    _, text = await alice.call("restart_service", {"service": "payments", "env": "prod"})
    rid = request_id_from(text)

    async with httpx2.AsyncClient(base_url=server.base) as anon:
        r = await anon.get(f"/jit/{rid}")
        assert r.status_code == 303 and r.headers["location"].startswith("/auth/login")
        r = await anon.post(f"/jit/{rid}/approve", data={"csrf": "x"})
        assert r.status_code == 303 and server.demo.store.get_request(rid).status == "pending"

    browser = Browser(server.base)
    await browser.open(f"/jit/{rid}")
    r = await browser.http.post(f"/jit/{rid}/approve", data={"csrf": "forged"})
    assert r.status_code == 400
    assert server.demo.store.get_request(rid).status == "pending"
    await browser.aclose()


async def test_stale_sign_in_must_reauthenticate_before_approving(server):
    alice = Agent(server.base, server.entra.access_token(ALICE))
    _, text = await alice.call("restart_service", {"service": "payments", "env": "prod"})
    rid = request_id_from(text)
    browser = Browser(server.base)
    page = await browser.open(f"/jit/{rid}")

    # 15 minutes pass: past the 10-minute re-auth window, inside the 30-minute request expiry.
    store = server.demo.store
    real_clock = store.clock
    store.clock = lambda: real_clock() + 15 * 60
    try:
        page = await browser.post(f"/jit/{rid}/approve", page)
        assert server.entra.last_authorize["prompt"] == "login"  # forced fresh sign-in
        assert store.get_request(rid).status == "pending"        # not approved yet
        page = await browser.post(f"/jit/{rid}/approve", page)   # approve again after re-auth
        assert store.get_request(rid).status == "approved"
    finally:
        store.clock = real_clock
    await browser.aclose()
