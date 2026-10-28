# From demo to production

In the demo the MCP server stores JIT requests and grants in SQLite. In production the
**identity governance platform is the system of record** and the MCP server only enforces.

| Role | Production | Demo |
|---|---|---|
| Eligibility, requests, approvals, grants, expiry, audit | Entra PIM or SailPoint | SQLite + `/jit` pages |
| Decision: may this identity run this action now? | PIM group membership via Graph, or SailPoint policy API | `app/jit.py` |
| Enforcement: allow or block the tool call | MCP server or MCP gateway | `app/server.py` |

## Options

**Entra PIM for Groups** (Entra ID P2 or Governance)
- Map each privileged tool/environment to a PIM-eligible group, e.g. `mcp-prod-restart`.
- Users activate the group in PIM (approval, MFA, time limit).
- On each call the MCP server checks live membership through Microsoft Graph (short cache).
  Don't rely on the token's `groups` claim: it is stale until the token refreshes.
- Grants are per group and last hours, so they are coarser than the demo's per-action grants.

**SailPoint (Privilege on Demand JIT, Agentic Fabric)**
- SailPoint holds JIT entitlements, approvals and audit.
- On each call the MCP server or gateway asks SailPoint's gateway access policy
  (identity + gateway + target + tool) for allow or deny.
- Closer to per-tool decisions while SailPoint stays the system of record.

**Short-lived credentials (with either)**
- On approval, issue credentials scoped to the action (GCP service-account impersonation,
  AWS STS, ...). The target system enforces the expiry, even if the MCP layer is bypassed.

## What stays in the MCP server

- Mapping from tool + arguments to an entitlement, group or policy (replaces `policy.yaml` rules).
- A short-lived decision cache.
- Returning the PIM or SailPoint request link to the agent instead of `/jit/<id>`.
- Agent-side audit, sent to the SIEM.

## Open gap

PIM and SailPoint grant entitlements (groups, roles, accounts). Agent JIT wants action-level
grants ("restart payments in prod, 15 minutes, once"). Either create narrow entitlements, or keep
a thin action-level check in the gateway backed by the entitlement.
