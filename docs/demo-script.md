# 10-minute demo script

Setup done beforehand: app registration, `.env`, `az login` for the scope, `docker compose up -d`.
Open two windows: a terminal for Claude Code, and a browser on `http://localhost:8000/jit`.

## 1. Identity (OAuth 2.0)

```bash
scripts/show-token.sh
```
Point out `aud`, `scp=mcp.access`, `oid`, and that the token came from Entra via auth code + PKCE.

```bash
scripts/smoke-test.sh
```
Shows the 401 + `resource_metadata` challenge without a token, and the tool list with one.

## 2. Start Claude Code

```bash
scripts/claude-jit.sh
```
Prompt: **"Who am I on jit-mcp?"** → `whoami` returns your name and object ID from the token.

## 3. Read-only and low-risk actions just work

**"List the prod services."** → no approval.
**"Restart orders in dev."** → runs immediately (policy: only prod needs JIT).

## 4. A privileged action is held

**"Restart payments in prod, it's leaking memory."**

Claude gets `JIT approval required ... JIT-XXXXXX` with a link and tells you nothing changed.
Show **"What's the status of payments in prod?"** → `last_actor` unchanged.

## 5. Approve

Open the link. Entra sign-in → the request page shows who asked, the exact action, the
justification Claude passed, and how long the grant will last. Click **Approve**.

Back in Claude Code: **"Approved, go ahead."** → it retries and succeeds. The result names the
grant and its expiry.

## 6. The grant is narrow

**"Now restart orders in prod too."** → new request: the grant only covered `payments/prod`.

## 7. Revoke

On the dashboard, **Revoke** the payments grant. **"Restart payments in prod again."** → held again.

## 8. Single use

**"Rotate the secret for inventory in dev."** → approve → runs once. Ask again → new approval needed.

## 9. Two-person rule (optional)

Set `approval_mode: two_person` in `policy.yaml`, `docker compose restart`. Trigger a prod restart.
Opening the link as yourself shows "you can't approve your own request". Sign in as the second
user in a private window and approve.

## 10. Audit

Dashboard → audit log, or `docker compose logs jit-mcp | grep jit.` — request, sign-in, approval,
use, execution, revocation, each with who and which request.

**Talking point:** the token proves identity for an hour; JIT decides each action, at the moment
it happens, with a human in the loop, and leaves no standing access behind.
