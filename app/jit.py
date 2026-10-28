"""The JIT authorization engine.

Every privileged tool call goes through `JitEngine.authorize()`:

1. Policy says whether this call (tool + arguments) needs JIT at all.
2. If it does, look for an *active grant* for the same user, tool and bound
   arguments. A grant is an approved request whose time window is still open.
3. No grant -> create (or reuse) a pending request and raise `JitRequired`,
   which the tool turns into an error message with the approval link.

Approval happens on the web page (app/web.py) after the approver signs in with
Entra ID. Grants expire on their own; they can also be revoked early.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any

from .entra import Principal
from .policy import Policy, ToolRule
from .store import JitRequest, Store


class JitRequired(Exception):
    def __init__(self, request: JitRequest, approval_url: str):
        self.request = request
        self.approval_url = approval_url
        super().__init__(f"JIT approval required ({request.id})")


class ApprovalError(Exception):
    """An approval/deny/revoke that is not allowed."""


@dataclass(frozen=True)
class Authorization:
    jit: bool
    request_id: str | None = None
    grant_expires_at: float | None = None


def fingerprint(tool: str, bound: dict[str, Any]) -> str:
    canonical = json.dumps({"tool": tool, "args": bound}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def new_request_id() -> str:
    return f"JIT-{secrets.token_hex(3).upper()}"


class JitEngine:
    def __init__(self, store: Store, policy: Policy, public_base_url: str):
        self.store = store
        self.policy = policy
        self.base_url = public_base_url.rstrip("/")

    def approval_url(self, request_id: str) -> str:
        return f"{self.base_url}/jit/{request_id}"

    # ---- housekeeping ---------------------------------------------------
    def sweep(self) -> None:
        """Mark pending requests and grants whose time is up as expired."""
        now = self.store.clock()
        for req in self.store.due_for_expiry(now):
            what = "grant" if req.status == "approved" else "request"
            self.store.update_request(req.id, status="expired")
            self.store.audit(f"jit.{what}_expired", actor_oid=req.requester_oid, actor_name=req.requester_name,
                             request_id=req.id, tool=req.tool, args=req.bound)

    # ---- the check every privileged call goes through -------------------
    def authorize(self, user: Principal, tool: str, args: dict[str, Any], justification: str = "") -> Authorization:
        self.sweep()
        rule = self.policy.rule_for(tool, args)
        if rule is None:
            return Authorization(jit=False)

        bound = rule.bound(args)
        fp = fingerprint(tool, bound)

        grant = self.store.find(user.oid, tool, fp, "approved")
        if grant:
            self._use_grant(grant, rule, user)
            return Authorization(jit=True, request_id=grant.id, grant_expires_at=grant.grant_expires_at)

        pending = self.store.find(user.oid, tool, fp, "pending")
        if pending:
            raise JitRequired(pending, self.approval_url(pending.id))

        req = self._create_request(user, rule, args, bound, fp, justification)
        raise JitRequired(req, self.approval_url(req.id))

    def _use_grant(self, grant: JitRequest, rule: ToolRule, user: Principal) -> None:
        fields: dict[str, Any] = {"use_count": grant.use_count + 1}
        if grant.single_use:
            fields["status"] = "used"
        self.store.update_request(grant.id, **fields)
        self.store.audit("jit.grant_used", actor_oid=user.oid, actor_name=user.label, request_id=grant.id,
                         tool=grant.tool, args=grant.bound, single_use=grant.single_use)

    def _create_request(self, user: Principal, rule: ToolRule, args: dict[str, Any], bound: dict[str, Any],
                        fp: str, justification: str) -> JitRequest:
        now = self.store.clock()
        req = JitRequest(
            id=new_request_id(), requester_oid=user.oid, requester_name=user.name,
            requester_username=user.username, tool=rule.tool, args=args, bound=bound, fingerprint=fp,
            justification=justification.strip()[:500], ttl_seconds=rule.ttl_seconds, single_use=rule.single_use,
            status="pending", created_at=now, request_expires_at=now + self.policy.request_expiry_seconds,
            decided_at=None, decided_by_oid=None, decided_by_name=None, grant_expires_at=None, use_count=0,
        )
        self.store.insert_request(req)
        self.store.audit("jit.request_created", actor_oid=user.oid, actor_name=user.label, request_id=req.id,
                         tool=req.tool, args=bound, justification=req.justification, client_app=user.client_app)
        return req

    # ---- decisions made on the approval page ----------------------------
    def can_approve(self, req: JitRequest, approver: Principal) -> str | None:
        """Return None if `approver` may approve `req`, else the reason they may not."""
        if req.status != "pending":
            return f"This request is {req.status}."
        if self.policy.approval_mode == "two_person" and approver.oid == req.requester_oid:
            return "Two-person rule: you can't approve your own request. Ask another approver to open this link."
        if not self.policy.may_approve(approver.username):
            return f"{approver.username} is not on the approver list in policy.yaml."
        return None

    def approve(self, request_id: str, approver: Principal) -> JitRequest:
        self.sweep()
        req = self._get(request_id)
        if reason := self.can_approve(req, approver):
            self.store.audit("jit.approval_blocked", actor_oid=approver.oid, actor_name=approver.label,
                             request_id=req.id, tool=req.tool, reason=reason)
            raise ApprovalError(reason)
        now = self.store.clock()
        self.store.update_request(req.id, status="approved", decided_at=now, decided_by_oid=approver.oid,
                                  decided_by_name=approver.label, grant_expires_at=now + req.ttl_seconds)
        self.store.audit("jit.approved", actor_oid=approver.oid, actor_name=approver.label, request_id=req.id,
                         tool=req.tool, args=req.bound, requester=req.requester_username,
                         ttl_seconds=req.ttl_seconds, self_approved=approver.oid == req.requester_oid)
        return self._get(request_id)

    def deny(self, request_id: str, approver: Principal) -> JitRequest:
        self.sweep()
        req = self._get(request_id)
        if req.status != "pending":
            raise ApprovalError(f"This request is {req.status}.")
        self.store.update_request(req.id, status="denied", decided_at=self.store.clock(),
                                  decided_by_oid=approver.oid, decided_by_name=approver.label)
        self.store.audit("jit.denied", actor_oid=approver.oid, actor_name=approver.label, request_id=req.id,
                         tool=req.tool, args=req.bound, requester=req.requester_username)
        return self._get(request_id)

    def revoke(self, request_id: str, actor: Principal) -> JitRequest:
        """End an active grant early. Revoking only removes access, so any signed-in user may do it."""
        self.sweep()
        req = self._get(request_id)
        if req.status != "approved":
            raise ApprovalError(f"Only an active grant can be revoked; this one is {req.status}.")
        self.store.update_request(req.id, status="revoked", grant_expires_at=self.store.clock())
        self.store.audit("jit.revoked", actor_oid=actor.oid, actor_name=actor.label, request_id=req.id,
                         tool=req.tool, args=req.bound, requester=req.requester_username)
        return self._get(request_id)

    def status(self, request_id: str, requester_oid: str) -> JitRequest | None:
        self.sweep()
        req = self.store.get_request(request_id)
        return req if req and req.requester_oid == requester_oid else None

    def active_grants(self, requester_oid: str | None = None) -> list[JitRequest]:
        self.sweep()
        return self.store.list_requests(status="approved", requester_oid=requester_oid)

    def _get(self, request_id: str) -> JitRequest:
        req = self.store.get_request(request_id)
        if not req:
            raise ApprovalError("Unknown request.")
        return req
