"""Unit tests for the JIT engine with a controllable clock (expiry without sleeping)."""

from __future__ import annotations

import pytest

from app.entra import Principal
from app.jit import ApprovalError, JitEngine, JitRequired, fingerprint
from app.policy import parse_policy
from app.store import Store

from .conftest import POLICY

ALICE = Principal(oid="a", name="Alice", username="alice@contoso.test", tenant_id="t")
BOB = Principal(oid="b", name="Bob", username="bob@contoso.test", tenant_id="t")
PROD = {"service": "payments", "env": "prod"}


class Clock:
    def __init__(self):
        self.now = 1_800_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


def engine(clock, **overrides) -> JitEngine:
    return JitEngine(Store(":memory:", clock=clock), parse_policy({**POLICY, **overrides}), "http://localhost:8000")


def request_for(eng, user=ALICE, tool="restart_service", args=PROD):
    with pytest.raises(JitRequired) as exc:
        eng.authorize(user, tool, args)
    return exc.value.request


def test_policy_scoping(clock):
    eng = engine(clock)
    assert eng.authorize(ALICE, "restart_service", {"service": "payments", "env": "dev"}).jit is False
    assert eng.authorize(ALICE, "list_services", {}).jit is False
    req = request_for(eng)
    assert req.bound == PROD and req.ttl_seconds == 15 * 60


def test_justification_does_not_change_binding(clock):
    eng = engine(clock)
    a = request_for(eng, args={**PROD, "reason": "one"})
    b = request_for(eng, args={**PROD, "reason": "two"})
    assert a.id == b.id


def test_grant_expires(clock):
    eng = engine(clock)
    req = request_for(eng)
    eng.approve(req.id, ALICE)
    clock.now += 14 * 60
    assert eng.authorize(ALICE, "restart_service", PROD).request_id == req.id
    clock.now += 2 * 60  # past 15 minutes
    new = request_for(eng)
    assert new.id != req.id
    assert eng.store.get_request(req.id).status == "expired"
    assert "jit.grant_expired" in [e["event"] for e in eng.store.recent_audit()]


def test_pending_request_expires(clock):
    eng = engine(clock)
    req = request_for(eng)
    clock.now += 31 * 60
    eng.sweep()
    assert eng.store.get_request(req.id).status == "expired"
    with pytest.raises(ApprovalError):
        eng.approve(req.id, ALICE)


def test_two_person_and_approver_list(clock):
    eng = engine(clock, approval_mode="two_person", approvers=["bob@contoso.test"])
    req = request_for(eng)
    with pytest.raises(ApprovalError, match="Two-person"):
        eng.approve(req.id, ALICE)
    carol = Principal(oid="c", name="Carol", username="carol@contoso.test", tenant_id="t")
    with pytest.raises(ApprovalError, match="approver list"):
        eng.approve(req.id, carol)
    assert eng.approve(req.id, BOB).status == "approved"


def test_cannot_decide_twice(clock):
    eng = engine(clock)
    req = request_for(eng)
    eng.deny(req.id, BOB)
    with pytest.raises(ApprovalError):
        eng.approve(req.id, BOB)


def test_fingerprint_is_order_independent():
    assert fingerprint("t", {"a": 1, "b": 2}) == fingerprint("t", {"b": 2, "a": 1})
    assert fingerprint("t", {"a": 1}) != fingerprint("t", {"a": 2})
