"""JIT policy: which tool calls need just-in-time approval, and on what terms.

Loaded from policy.yaml. Tools that are not listed run without JIT (they are
still behind Entra sign-in and the `mcp.access` scope).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

ApprovalMode = Literal["self", "two_person"]


@dataclass(frozen=True)
class ToolRule:
    tool: str
    ttl_seconds: int
    bind_args: tuple[str, ...]
    single_use: bool = False
    # None = always; otherwise {arg_name: [values that require JIT]}
    jit_when: dict[str, tuple[Any, ...]] | None = None

    def applies_to(self, args: dict[str, Any]) -> bool:
        if self.jit_when is None:
            return True
        return any(args.get(arg) in values for arg, values in self.jit_when.items())

    def bound(self, args: dict[str, Any]) -> dict[str, Any]:
        """The arguments a grant is pinned to (e.g. service + env, not the free-text reason)."""
        return {k: args.get(k) for k in self.bind_args}


@dataclass(frozen=True)
class Policy:
    approval_mode: ApprovalMode = "self"
    approvers: tuple[str, ...] = ()  # usernames/emails allowed to approve; empty = any tenant user
    request_expiry_seconds: int = 30 * 60
    reauth_seconds: int = 10 * 60
    rules: dict[str, ToolRule] = field(default_factory=dict)

    def rule_for(self, tool: str, args: dict[str, Any]) -> ToolRule | None:
        rule = self.rules.get(tool)
        return rule if rule and rule.applies_to(args) else None

    def may_approve(self, username: str) -> bool:
        return not self.approvers or username.lower() in self.approvers


def _seconds(spec: dict[str, Any], key: str, default: int) -> int:
    if f"{key}_seconds" in spec:
        return int(spec[f"{key}_seconds"])
    if f"{key}_minutes" in spec:
        return int(float(spec[f"{key}_minutes"]) * 60)
    return default


def parse_policy(data: dict[str, Any]) -> Policy:
    mode = data.get("approval_mode", "self")
    if mode not in ("self", "two_person"):
        raise ValueError("approval_mode must be 'self' or 'two_person'")

    rules: dict[str, ToolRule] = {}
    for tool, spec in (data.get("tools") or {}).items():
        spec = spec or {}
        when = spec.get("jit_when", "always")
        jit_when = None
        if when != "always":
            if not isinstance(when, dict):
                raise ValueError(f"{tool}.jit_when must be 'always' or a mapping of arg -> values")
            jit_when = {k: tuple(v if isinstance(v, list) else [v]) for k, v in when.items()}
        rules[tool] = ToolRule(
            tool=tool,
            ttl_seconds=_seconds(spec, "ttl", 15 * 60),
            bind_args=tuple(spec.get("bind_args", [])),
            single_use=bool(spec.get("single_use", False)),
            jit_when=jit_when,
        )

    return Policy(
        approval_mode=mode,
        approvers=tuple(a.lower() for a in data.get("approvers") or []),
        request_expiry_seconds=_seconds(data, "request_expiry", 30 * 60),
        reauth_seconds=_seconds(data, "reauth", 10 * 60),
        rules=rules,
    )


def load_policy(path: str | Path) -> Policy:
    return parse_policy(yaml.safe_load(Path(path).read_text()) or {})
