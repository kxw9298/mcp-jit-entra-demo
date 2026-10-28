# MCP + Entra ID OAuth 2.0 + Just-in-Time authorization

A small, runnable demo of how to put **just-in-time (JIT) approval** in front of privileged MCP tools,
with **Microsoft Entra ID** for sign-in, used from **Claude Code**.

- **OAuth 2.0 answers "who is calling?"** Claude Code sends an Entra ID access token. The MCP server
  checks signature, issuer, tenant, audience and the `mcp.access` scope on every request.
- **JIT answers "may this person do *this* right now?"** Privileged tool calls are blocked until a
  human approves that exact action on a web page, after signing in with Entra ID. The grant is
  pinned to the user, the tool and its arguments, expires on its own, and can be revoked.

No standing access: a valid token alone can read, but cannot restart prod.

```
> restart the payments service in prod, it's leaking memory

● jit-mcp - restart_service (service: "payments", env: "prod", reason: "memory leak")
  ⎿ Error: JIT approval required. Nothing was changed.
    Request: JIT-4F2A9C (pending)
    Approve: http://localhost:8000/jit/JIT-4F2A9C
    Grant:   lasts 15 min after approval and covers only service=payments, env=prod.

● Prod restarts need just-in-time approval. Open the link, approve, and tell me when it's done.

> approved

● jit-mcp - restart_service (service: "payments", env: "prod")
  ⎿ {"result": "payments (prod) restarted", "by": "Ke Wang", "jit_request": "JIT-4F2A9C", ...}
```

## How it works

```mermaid
sequenceDiagram
    autonumber
    actor U as You
    participant CC as Claude Code
    participant AZ as Azure CLI
    participant E as Entra ID
    participant M as MCP server (Docker)
    participant W as Approval page (same server)

    U->>AZ: az login (once)
    AZ->>E: OAuth 2.0 auth code + PKCE
    E-->>AZ: access token (aud=api://<app>, scp=mcp.access)
    U->>CC: scripts/claude-jit.sh
    CC->>M: tools/call restart_service(prod) + Bearer token
    M->>M: validate token (JWKS, iss, tid, aud, scp)
    M->>M: JIT policy: prod restart needs a grant → none
    M-->>CC: error: JIT-4F2A9C pending + approval link
    U->>W: open link
    W->>E: sign in (auth code + PKCE)
    E-->>W: ID token
    U->>W: Approve (re-auth if sign-in is stale)
    W->>W: grant: user + tool + {service, env}, 15 min
    CC->>M: retry restart_service(prod)
    M->>M: grant found → run, audit
    M-->>CC: restarted
```

More detail: [docs/architecture.md](docs/architecture.md).

## What's in the box

| Path | What it is |
|---|---|
| `app/entra.py` | Entra access-token and ID-token validation (JWKS, v1 + v2 tokens) |
| `app/jit.py` | JIT engine: policy check, requests, grants, approve / deny / revoke, expiry |
| `app/server.py` | MCP server (Streamable HTTP, MCP Python SDK 2.x) and its tools |
| `app/web.py` | Approval page with Entra sign-in (public client, auth code + PKCE, no secret) |
| `policy.yaml` | Which tools need JIT, grant length, argument binding, approval mode |
| `scripts/` | Create the Entra app, get a token, start Claude Code, smoke test |
| `tests/` | 22 tests against a mock Entra ID, end to end over real HTTP |

Tools exposed to the agent:

| Tool | JIT |
|---|---|
| `whoami`, `list_services`, `get_service_status` | No (read-only) |
| `restart_service` | In prod |
| `scale_service` | In prod |
| `rotate_secret` | Always, single use |
| `check_jit_request`, `list_my_jit_grants` | No |

The "infrastructure" is a fake inventory in SQLite, so the demo is safe to run anywhere.

## Quick start (macOS)

Needs Docker Desktop, the Azure CLI (`brew install azure-cli`), Claude Code, and an Entra tenant
(the free tier is enough; your Azure subscription's "Default Directory" works).

```bash
git clone https://github.com/kxw9298/mcp-jit-entra-demo.git
cd mcp-jit-entra-demo

# 1. Entra app registration + .env (or do it in the portal: docs/entra-setup.md)
az login --allow-no-subscriptions
scripts/create-entra-app.sh

# 2. Sign in for the MCP API scope (prints the exact command if needed)
source .env
az login --tenant "$ENTRA_TENANT_ID" --scope "api://$ENTRA_CLIENT_ID/mcp.access" --allow-no-subscriptions

# 3. Run the server
docker compose up -d --build
scripts/smoke-test.sh

# 4. Start Claude Code with a fresh token
scripts/claude-jit.sh
```

In Claude Code, approve the project MCP server `jit-mcp` when asked, then run `/mcp` to check it is
connected. Try: *"who am I on jit-mcp?"*, then *"restart payments in prod"*.

Step-by-step walkthrough for a live demo: [docs/demo-script.md](docs/demo-script.md).

## Why the token comes from the Azure CLI

Claude Code can do the MCP OAuth flow itself, and this server publishes the standard
[RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) protected-resource metadata for it. With Entra ID as the
authorization server that flow currently fails with `AADSTS9010010`: the client sends the MCP
server URL as the `resource` parameter, and Entra only accepts its own `api://` identifier there
([open issue](https://claudeissues.com/issue/89438-mcp-oauth-against-microsoft-entra-id-aadsts9010010-on-connect-aadsts650053-on-re)).

So the demo uses the Azure CLI as the OAuth client (still auth code + PKCE against Entra), and
`scripts/claude-jit.sh` passes the token to Claude Code through `MCP_JIT_TOKEN`, which `.mcp.json`
puts in the `Authorization` header. Tokens last about an hour: restart the script to refresh.
Nothing on the server side changes when native OAuth starts working.

## Policy

```yaml
approval_mode: self          # or two_person: someone else must approve
approvers: []                # optional allow-list of approver usernames
request_expiry_minutes: 30
reauth_minutes: 10           # approver must have signed in recently, else sign in again

tools:
  restart_service:
    jit_when: { env: [prod] }
    ttl_minutes: 15
    bind_args: [service, env]
  rotate_secret:
    jit_when: always
    ttl_minutes: 5
    bind_args: [service, env]
    single_use: true
```

`policy.yaml` is mounted into the container; run `docker compose restart` after editing it.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

The tests start a mock Entra ID (JWKS, authorize and token endpoints with PKCE) and the real server
on local ports, then drive it with the MCP Python client and an HTTP "browser". They cover token
rejection (audience, tenant, expiry, signature, scope), the full request → approve → retry flow,
argument binding, revocation, single-use grants, denial, the two-person rule, CSRF, and forced
re-authentication before approval.

## Docs

- [docs/architecture.md](docs/architecture.md): components, token checks, JIT data model
- [docs/entra-setup.md](docs/entra-setup.md): app registration in the portal, by hand
- [docs/demo-script.md](docs/demo-script.md): a 10-minute live demo
- [docs/security-notes.md](docs/security-notes.md): what this demo does and doesn't protect against, and how to harden it

## License

MIT
