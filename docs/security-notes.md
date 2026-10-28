# Security notes

This is a demo. It shows the pattern; it is not a hardened product.

## What it protects against

| Threat | Control |
|---|---|
| Anyone on the network calling the MCP server | Port bound to `127.0.0.1`; every request needs a valid Entra token |
| A token minted for another API or tenant being replayed here | Audience, issuer and `tid` checks; JWKS signature check |
| App-only (client credentials) tokens acting with no human | `scp` claim required |
| An agent (or prompt injection) running a destructive action on its own | Privileged tools need a human-approved JIT grant |
| An approval for one thing being used for another | Grant bound to user + tool + bound arguments (fingerprint) |
| Long-lived standing access | Grants expire (minutes), can be revoked, can be single-use |
| Self-approval | `two_person` mode, enforced server-side; optional approver allow-list |
| Stale browser sessions approving things | Approver must have signed in within `reauth_minutes`, else `prompt=login` |
| CSRF on the approval page | Per-session token on every POST, `SameSite=Lax` cookie |
| Unreviewed changes | Every request, decision, use and execution is audited with who and which request |

## What it does not do (and how to get there)

- **Downstream credentials.** The fake backend trusts the server. In real use, mint short-lived
  credentials *at approval time* (for example Azure PIM for Groups activation via Microsoft Graph,
  GCP service-account impersonation with a short lifetime, AWS STS with a session policy) so the
  JIT boundary also holds at the target system, not only at the MCP layer.
- **Token passthrough.** Correctly absent: the user's token is never forwarded. Keep it that way.
- **MFA / authentication strength.** Enforce with Conditional Access on the app (needs Entra ID P1),
  or check the `amr`/`acrs` claims on the approval page's ID token.
- **High availability.** SQLite and in-process sweeping assume one instance. Use Postgres or Redis
  for multiple replicas.
- **HTTPS.** Fine on localhost. Anywhere else, terminate TLS in front and set `PUBLIC_BASE_URL` to the
  `https://` URL (the session cookie then becomes `Secure`).
- **Native MCP OAuth in Claude Code.** Blocked by an Entra `resource` parameter incompatibility
  (`AADSTS9010010`), so tokens come from the Azure CLI for now. The server already serves RFC 9728
  metadata, so nothing changes here when the client side is fixed.
- **Argument semantics.** The binding is exact-match on the arguments listed in `bind_args`.
  Arguments not listed (like `reason`) can change freely, so don't leave a security-relevant
  argument out of `bind_args`.
- **Approval fatigue.** A human who clicks Approve on everything is not a control. Show the exact
  action, keep grants short, and route high-risk tools to a different approver.
