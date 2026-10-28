"""MCP server: tools, Entra-protected transport, and app assembly."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Literal

from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

from .config import Settings, load_settings
from .entra import EntraTokenVerifier, EntraValidator, Principal
from .jit import JitEngine, JitRequired
from .policy import Policy, load_policy
from .store import JitRequest, Store
from .web import register_web_routes

log = logging.getLogger(__name__)

Env = Literal["dev", "prod"]

INSTRUCTIONS = """\
Demo infrastructure tools protected by Microsoft Entra ID sign-in plus just-in-time (JIT) approval.
Read-only tools run immediately. Changes to prod (restart_service, scale_service) and every
rotate_secret call need a JIT grant. When a tool reports "JIT approval required", nothing was
changed: show the user the approval link from the message, wait for them to say it is approved,
then call check_jit_request or retry with exactly the same arguments. Never try to work around a
JIT denial by changing arguments or using another tool."""


def iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds") if ts else None


def describe_call(tool: str, args: dict[str, Any]) -> str:
    return f"{tool}({', '.join(f'{k}={v!r}' for k, v in args.items())})"


def jit_message(exc: JitRequired) -> str:
    req = exc.request
    minutes = max(1, round(req.ttl_seconds / 60))
    scope = ", ".join(f"{k}={v}" for k, v in req.bound.items()) or "these arguments"
    return (
        "JIT approval required. Nothing was changed.\n"
        f"Request: {req.id} (pending)\n"
        f"Action:  {describe_call(req.tool, req.bound)}\n"
        f"Approve: {exc.approval_url}\n"
        f"Grant:   lasts {minutes} min after approval and covers only {scope}"
        f"{' (single use)' if req.single_use else ''}.\n"
        f"Next:    ask the user to open the link and approve, then call check_jit_request('{req.id}') "
        "or retry with the same arguments."
    )


def request_view(req: JitRequest) -> dict[str, Any]:
    return {
        "request_id": req.id,
        "status": req.status,
        "tool": req.tool,
        "arguments": req.bound,
        "justification": req.justification,
        "created_at": iso(req.created_at),
        "decided_by": req.decided_by_name,
        "decided_at": iso(req.decided_at),
        "grant_expires_at": iso(req.grant_expires_at),
        "single_use": req.single_use,
        "uses": req.use_count,
    }


def build_mcp(settings: Settings, engine: JitEngine, store: Store, validator: EntraValidator) -> MCPServer:
    mcp = MCPServer(
        name="jit-mcp",
        title="JIT-protected infrastructure (demo)",
        instructions=INSTRUCTIONS,
        version="0.1.0",
        token_verifier=EntraTokenVerifier(validator),
        auth=AuthSettings(
            issuer_url=settings.v2_issuer,  # advertised in protected-resource metadata
            resource_server_url=settings.resource_url,
            required_scopes=[settings.full_scope],
            validate_token_resource=False,  # EntraValidator checks the audience itself
        ),
    )

    def current_user() -> Principal:
        token = get_access_token()
        if token is None or not token.claims:
            raise ToolError("Not authenticated.")
        return Principal.from_claims(token.claims)

    def require(tool: str, args: dict[str, Any], reason: str = "") -> tuple[Principal, Any]:
        user = current_user()
        try:
            return user, engine.authorize(user, tool, args, reason)
        except JitRequired as exc:
            raise ToolError(jit_message(exc)) from None

    def get_service_or_fail(service: str, env: str) -> dict[str, Any]:
        svc = store.service(service, env)
        if not svc:
            names = sorted({s["name"] for s in store.services()})
            raise ToolError(f"Unknown service {service!r}. Known services: {', '.join(names)}.")
        return svc

    def record(user: Principal, tool: str, args: dict[str, Any], auth: Any, **result: Any) -> None:
        store.audit("tool.executed", actor_oid=user.oid, actor_name=user.label, request_id=auth.request_id,
                    tool=tool, args=args, jit=auth.jit, **result)

    # ---- identity / read-only tools ------------------------------------
    @mcp.tool()
    def whoami() -> dict[str, Any]:
        """Show who the MCP server thinks you are, based on your Entra ID access token."""
        token = get_access_token()
        user = current_user()
        claims = token.claims or {}
        return {
            "name": user.name,
            "username": user.username,
            "object_id": user.oid,
            "tenant_id": user.tenant_id,
            "oauth_client": user.client_app,
            "scopes": token.scopes,
            "token_version": claims.get("ver"),
            "token_expires_at": iso(token.expires_at),
        }

    @mcp.tool()
    def list_services(env: Env | None = None) -> list[dict[str, Any]]:
        """List demo services and their state. Read-only, no approval needed."""
        current_user()
        return [
            {k: s[k] for k in ("name", "env", "status", "replicas", "version")} for s in store.services(env)
        ]

    @mcp.tool()
    def get_service_status(service: str, env: Env) -> dict[str, Any]:
        """Get one service's status, including the last change and who made it. Read-only."""
        current_user()
        svc = get_service_or_fail(service, env)
        return {**{k: v for k, v in svc.items() if k != "last_change"}, "last_change": iso(svc["last_change"])}

    # ---- privileged tools (JIT per policy.yaml) ------------------------
    @mcp.tool()
    def restart_service(service: str, env: Env, reason: str = "") -> dict[str, Any]:
        """Restart a service. Restarting in prod needs a JIT grant; dev does not.

        `reason` is shown to the approver as the justification.
        """
        args = {"service": service, "env": env}
        get_service_or_fail(service, env)
        user, auth = require("restart_service", args, reason)
        now = store.clock()
        store.update_service(service, env, status="running", last_change=now, last_actor=user.label,
                             last_action="restart")
        record(user, "restart_service", args, auth, outcome="restarted")
        return {"result": f"{service} ({env}) restarted", "by": user.label, "jit_request": auth.request_id,
                "grant_expires_at": iso(auth.grant_expires_at)}

    @mcp.tool()
    def scale_service(service: str, env: Env, replicas: int, reason: str = "") -> dict[str, Any]:
        """Change a service's replica count (1-20). Scaling in prod needs a JIT grant."""
        if not 1 <= replicas <= 20:
            raise ToolError("replicas must be between 1 and 20.")
        args = {"service": service, "env": env, "replicas": replicas}
        before = get_service_or_fail(service, env)["replicas"]
        user, auth = require("scale_service", args, reason)
        store.update_service(service, env, replicas=replicas, last_change=store.clock(), last_actor=user.label,
                             last_action=f"scale {before}->{replicas}")
        record(user, "scale_service", args, auth, outcome=f"scaled {before}->{replicas}")
        return {"result": f"{service} ({env}) scaled from {before} to {replicas} replicas", "by": user.label,
                "jit_request": auth.request_id, "grant_expires_at": iso(auth.grant_expires_at)}

    @mcp.tool()
    def rotate_secret(service: str, env: Env, reason: str = "") -> dict[str, Any]:
        """Rotate a service's credentials. Always needs a single-use JIT grant."""
        args = {"service": service, "env": env}
        svc = get_service_or_fail(service, env)
        user, auth = require("rotate_secret", args, reason)
        new_ver = svc["secret_ver"] + 1
        store.update_service(service, env, secret_ver=new_ver, last_change=store.clock(), last_actor=user.label,
                             last_action=f"rotate secret v{new_ver}")
        record(user, "rotate_secret", args, auth, outcome=f"secret v{new_ver}")
        return {"result": f"{service} ({env}) secret rotated to v{new_ver}", "by": user.label,
                "jit_request": auth.request_id, "note": "Single-use grant: it is now consumed."}

    # ---- JIT helpers ---------------------------------------------------
    @mcp.tool()
    def check_jit_request(request_id: str) -> dict[str, Any]:
        """Check the status of one of your JIT requests (pending, approved, denied, expired, revoked, used)."""
        user = current_user()
        req = engine.status(request_id.strip().upper(), user.oid)
        if not req:
            raise ToolError(f"No JIT request {request_id} found for you.")
        view = request_view(req)
        if req.status == "pending":
            view["approval_url"] = engine.approval_url(req.id)
        return view

    @mcp.tool()
    def list_my_jit_grants() -> list[dict[str, Any]]:
        """List your active JIT grants and when each one expires."""
        user = current_user()
        return [request_view(r) for r in engine.active_grants(user.oid)]

    return mcp


@dataclass
class Demo:
    app: ASGIApp
    mcp: MCPServer
    engine: JitEngine
    store: Store
    settings: Settings
    policy: Policy


def build(settings: Settings | None = None, policy: Policy | None = None,
          clock: Callable[[], float] = time.time) -> Demo:
    settings = settings or load_settings()
    policy = policy or load_policy(settings.policy_path)
    store = Store(settings.db_path, clock=clock)
    engine = JitEngine(store, policy, settings.public_base_url)
    validator = EntraValidator(settings)

    mcp = build_mcp(settings, engine, store, validator)
    register_web_routes(mcp, settings, engine, store, validator)

    starlette_app = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=settings.allowed_hosts, allowed_origins=settings.allowed_origins
        ),
    )
    app = SessionMiddleware(
        starlette_app,
        secret_key=settings.session_secret,
        session_cookie="jit_session",
        max_age=8 * 3600,
        same_site="lax",
        https_only=settings.secure_cookies,
    )
    log.info("JIT MCP ready: resource=%s policy=%s mode=%s", settings.resource_url, settings.policy_path,
             policy.approval_mode)
    return Demo(app=app, mcp=mcp, engine=engine, store=store, settings=settings, policy=policy)
