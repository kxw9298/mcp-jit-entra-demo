"""Approval web pages. Approvers sign in with Entra ID (auth code + PKCE, public client)."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlencode

import httpx2
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.templating import Jinja2Templates

from .config import Settings
from .entra import EntraValidator, Principal
from .jit import ApprovalError, JitEngine
from .store import Store

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

log = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _fmt_ts(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"


def _relative(ts: float | None, now: float) -> str:
    if not ts:
        return ""
    delta = int(ts - now)
    span = abs(delta)
    text = f"{span}s" if span < 90 else f"{round(span / 60)} min" if span < 5400 else f"{round(span / 3600, 1)} h"
    return f"in {text}" if delta > 0 else f"{text} ago"


templates.env.filters["ts"] = _fmt_ts


def _safe_next(value: str | None) -> str:
    return value if value and value.startswith("/") and not value.startswith("//") else "/jit"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register_web_routes(mcp: "MCPServer", settings: Settings, engine: JitEngine, store: Store,
                        validator: EntraValidator, proxy=None) -> None:
    policy = engine.policy

    def session_user(request: Request) -> Principal | None:
        u = request.session.get("user")
        return Principal(oid=u["oid"], name=u["name"], username=u["username"], tenant_id=u["tid"]) if u else None

    def login_redirect(request: Request, force: bool = False) -> RedirectResponse:
        query = {"next": request.url.path}
        if force:
            query["force"] = "1"
        return RedirectResponse(f"/auth/login?{urlencode(query)}", status_code=303)

    def csrf_token(request: Request) -> str:
        if "csrf" not in request.session:
            request.session["csrf"] = secrets.token_urlsafe(24)
        return request.session["csrf"]

    async def csrf_ok(request: Request) -> bool:
        form = await request.form()
        sent = form.get("csrf", "")
        return bool(sent) and secrets.compare_digest(str(sent), request.session.get("csrf", ""))

    def page(request: Request, name: str, status_code: int = 200, **ctx) -> Response:
        user = session_user(request)
        now = store.clock()
        return templates.TemplateResponse(
            request, name,
            {"user": user, "now": now, "rel": lambda ts: _relative(ts, now), "policy": policy,
             "csrf": csrf_token(request) if user else "", **ctx},
            status_code=status_code,
        )

    def message(request: Request, title: str, body: str, status_code: int = 200) -> Response:
        return page(request, "message.html", status_code=status_code, title=title, body=body)

    # ---- misc ------------------------------------------------------------
    @mcp.custom_route("/", methods=["GET"])
    async def root(request: Request) -> Response:
        return RedirectResponse("/jit", status_code=303)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    # ---- Entra sign-in ---------------------------------------------------
    @mcp.custom_route("/auth/login", methods=["GET"])
    async def login(request: Request) -> Response:
        verifier, challenge = _pkce()
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        request.session["oauth"] = {"state": state, "nonce": nonce, "verifier": verifier,
                                    "next": _safe_next(request.query_params.get("next"))}
        params = {
            "client_id": settings.client_id,
            "response_type": "code",
            "redirect_uri": settings.redirect_uri,
            "response_mode": "query",
            "scope": "openid profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            # force=1 is used to re-check the approver's identity right before approving.
            "prompt": "login" if request.query_params.get("force") == "1" else "select_account",
        }
        return RedirectResponse(f"{settings.authorize_endpoint}?{urlencode(params)}", status_code=303)

    @mcp.custom_route("/auth/callback", methods=["GET"])
    async def callback(request: Request) -> Response:
        qp = request.query_params
        # The same redirect URI serves two flows: MCP client sign-in (proxied) and approval-page sign-in.
        if proxy is not None and proxy.is_proxy_state(qp.get("state")):
            return await proxy.handle_entra_callback(request)
        if "error" in qp:
            return message(request, "Sign-in failed", f"{qp.get('error')}: {qp.get('error_description', '')}", 400)
        oauth = request.session.pop("oauth", None)
        if not oauth or not secrets.compare_digest(qp.get("state", ""), oauth["state"]):
            return message(request, "Sign-in failed", "The sign-in state did not match. Please try again.", 400)

        async with httpx2.AsyncClient(timeout=20) as client:
            resp = await client.post(settings.token_endpoint, data={
                "client_id": settings.client_id,
                "grant_type": "authorization_code",
                "code": qp.get("code", ""),
                "redirect_uri": settings.redirect_uri,
                "code_verifier": oauth["verifier"],
                "scope": "openid profile",
            })
        if resp.status_code != 200:
            detail = resp.json().get("error_description", resp.text) if resp.headers.get(
                "content-type", "").startswith("application/json") else resp.text
            log.warning("token exchange failed: %s", detail)
            return message(request, "Sign-in failed", f"Entra ID rejected the code exchange: {detail}", 400)

        try:
            claims = await validator.validate_id_token(resp.json()["id_token"], oauth["nonce"])
        except Exception as exc:
            log.warning("id_token rejected: %s", exc)
            return message(request, "Sign-in failed", f"The ID token was not valid: {exc}", 400)

        user = Principal.from_claims(claims)
        request.session["user"] = {"oid": user.oid, "name": user.name, "username": user.username,
                                   "tid": user.tenant_id, "login_at": store.clock()}
        store.audit("web.signed_in", actor_oid=user.oid, actor_name=user.label)
        return RedirectResponse(oauth["next"], status_code=303)

    @mcp.custom_route("/auth/logout", methods=["GET"])
    async def logout(request: Request) -> Response:
        request.session.clear()
        return message(request, "Signed out",
                       "You are signed out of the approval page. Sign in again to pick a different account.")

    # ---- dashboard and request pages --------------------------------------
    @mcp.custom_route("/jit", methods=["GET"])
    async def dashboard(request: Request) -> Response:
        if not session_user(request):
            return login_redirect(request)
        engine.sweep()
        return page(request, "dashboard.html",
                    pending=store.list_requests(status="pending"),
                    grants=store.list_requests(status="approved"),
                    history=[r for r in store.list_requests(limit=30) if r.status not in ("pending", "approved")],
                    audit=store.recent_audit(40))

    @mcp.custom_route("/jit/{request_id}", methods=["GET"])
    async def show_request(request: Request) -> Response:
        user = session_user(request)
        if not user:
            return login_redirect(request)
        engine.sweep()
        req = store.get_request(request.path_params["request_id"].upper())
        if not req:
            return message(request, "Not found", "No JIT request with that ID.", 404)
        login_at = request.session["user"].get("login_at", 0)
        return page(request, "request.html", req=req,
                    blocked=engine.can_approve(req, user),
                    reauth_needed=store.clock() - login_at > policy.reauth_seconds,
                    approval_url=engine.approval_url(req.id),
                    flash=request.query_params.get("done"))

    async def decide(request: Request, action: str) -> Response:
        user = session_user(request)
        if not user:
            return login_redirect(request)
        request_id = request.path_params["request_id"].upper()
        if not await csrf_ok(request):
            return message(request, "Request rejected", "Missing or invalid form token. Reload the page.", 400)
        if action == "approve":
            login_at = request.session["user"].get("login_at", 0)
            if store.clock() - login_at > policy.reauth_seconds:
                # Step-up: make the approver sign in again before granting access.
                return RedirectResponse(f"/auth/login?{urlencode({'next': f'/jit/{request_id}', 'force': '1'})}",
                                        status_code=303)
        try:
            getattr(engine, action)(request_id, user)
        except ApprovalError as exc:
            return message(request, "Not allowed", str(exc), 403)
        return RedirectResponse(f"/jit/{request_id}?done={action}", status_code=303)

    @mcp.custom_route("/jit/{request_id}/approve", methods=["POST"])
    async def approve(request: Request) -> Response:
        return await decide(request, "approve")

    @mcp.custom_route("/jit/{request_id}/deny", methods=["POST"])
    async def deny(request: Request) -> Response:
        return await decide(request, "deny")

    @mcp.custom_route("/jit/{request_id}/revoke", methods=["POST"])
    async def revoke(request: Request) -> Response:
        return await decide(request, "revoke")
