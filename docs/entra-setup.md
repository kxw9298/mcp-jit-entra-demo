# Entra ID setup

One app registration does both jobs: it is the **API** that Claude Code's token is for, and the
**public client** the approval page signs users in with. No client secret is needed.

`scripts/create-entra-app.sh` does all of this with the Azure CLI. The portal steps below do the same.

## In the portal (entra.microsoft.com)

1. **App registrations → New registration**
   - Name: `mcp-jit-demo`
   - Supported account types: *Accounts in this organizational directory only*
   - Redirect URI: platform **Public client/native (mobile & desktop)**, URI
     `http://localhost:8000/auth/callback`
   - Register. Copy the **Application (client) ID** and **Directory (tenant) ID**.

2. **Expose an API**
   - Application ID URI → **Add** → keep `api://<client-id>` → Save.
   - **Add a scope**: name `mcp.access`, who can consent *Admins and users*, display name
     "Use the JIT MCP server", description "Call the JIT-protected MCP server as the signed-in user", enabled.
   - **Add a client application**: `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI), tick
     `api://<client-id>/mcp.access`. This lets `az` get a token for the API without a consent prompt.

3. Nothing under *Certificates & secrets* or *API permissions* is needed.

4. Copy `.env.example` to `.env` and fill in `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, and a random
   `SESSION_SECRET` (`openssl rand -base64 32`).

## Get a token from the CLI (optional, for scripts/smoke-test.sh)

```bash
source .env
az login --tenant "$ENTRA_TENANT_ID" --scope "api://$ENTRA_CLIENT_ID/mcp.access" --allow-no-subscriptions
scripts/show-token.sh     # decode it: aud, scp, oid, exp
```

You should see `aud = api://<client-id>`, `scp = mcp.access`, `ver = 1.0`. The server also accepts
v2 tokens if you set `requestedAccessTokenVersion: 2` in the app manifest.

## Two-person approval

For `approval_mode: two_person` you need a second user in the tenant (Users → New user). Open the
approval link in a private browser window and sign in as that user. Optionally put their username
in `approvers:` in `policy.yaml`.

## Troubleshooting

| Error | Cause / fix |
|---|---|
| `AADSTS65001` consent required (from `az`) | Azure CLI isn't pre-authorized: redo step 2's *Add a client application*. |
| `AADSTS500011` resource principal not found | The App ID URI isn't set, or the service principal wasn't created (`az ad sp create --id <client-id>`). |
| `AADSTS50011` redirect URI mismatch on the approval page | Redirect URI must be exactly `PUBLIC_BASE_URL/auth/callback` under *Mobile and desktop*. |
| `AADSTS7000218` client_secret required | The redirect URI was added under *Web* instead of *Mobile and desktop applications*. |
| MCP server returns 401 | Run `/mcp` → jit-mcp → Authenticate again. Check `docker compose logs` for "rejected bearer token". |
| Consent screen on first sign-in | Expected: it asks for `mcp.access` and offline access (for refresh). Accept once. |
