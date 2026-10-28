#!/usr/bin/env bash
# Create the Entra ID app registration for this demo with the Azure CLI, then write .env.
#
#   az login --allow-no-subscriptions        # as a user who can create app registrations
#   scripts/create-entra-app.sh [display-name] [public-base-url]
#
# What it creates (one app registration, no client secret):
#   * Expose an API: App ID URI api://<client-id>, delegated scope "mcp.access"
#   * Azure CLI pre-authorized for that scope (so `az account get-access-token` works without a consent prompt)
#   * Public client redirect URI <public-base-url>/auth/callback (approval page sign-in, auth code + PKCE)
#   * A service principal (enterprise app) so users in the tenant can sign in
set -euo pipefail

NAME="${1:-mcp-jit-demo}"
BASE_URL="${2:-http://localhost:8000}"
AZURE_CLI_APP_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GRAPH="https://graph.microsoft.com/v1.0"

command -v az >/dev/null || { echo "Install the Azure CLI first: brew install azure-cli" >&2; exit 1; }
TENANT_ID="$(az account show --query tenantId -o tsv)"
echo "Tenant: $TENANT_ID"

APP_ID="$(az ad app list --display-name "$NAME" --query '[0].appId' -o tsv)"
if [[ -z "$APP_ID" ]]; then
  echo "Creating app registration '$NAME'..."
  APP_ID="$(az ad app create --display-name "$NAME" --sign-in-audience AzureADMyOrg \
    --public-client-redirect-uris "$BASE_URL/auth/callback" --query appId -o tsv)"
else
  echo "Reusing existing app registration '$NAME' ($APP_ID)"
fi
OBJECT_ID="$(az ad app show --id "$APP_ID" --query id -o tsv)"

# Scope ID: keep the existing one if the scope is already there.
SCOPE_ID="$(az ad app show --id "$APP_ID" --query "api.oauth2PermissionScopes[?value=='mcp.access'].id | [0]" -o tsv)"
[[ -z "$SCOPE_ID" ]] && SCOPE_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

echo "Setting App ID URI and the mcp.access scope..."
az rest --method PATCH --url "$GRAPH/applications/$OBJECT_ID" --headers "Content-Type=application/json" --body "{
  \"identifierUris\": [\"api://$APP_ID\"],
  \"publicClient\": {\"redirectUris\": [\"$BASE_URL/auth/callback\"]},
  \"api\": {\"oauth2PermissionScopes\": [{
    \"id\": \"$SCOPE_ID\", \"value\": \"mcp.access\", \"type\": \"User\", \"isEnabled\": true,
    \"adminConsentDisplayName\": \"Use the JIT MCP server\",
    \"adminConsentDescription\": \"Lets the app call the JIT-protected MCP server as the signed-in user.\",
    \"userConsentDisplayName\": \"Use the JIT MCP server\",
    \"userConsentDescription\": \"Lets the app call the JIT-protected MCP server as you.\"
  }]}
}"

echo "Pre-authorizing Azure CLI for mcp.access..."
az rest --method PATCH --url "$GRAPH/applications/$OBJECT_ID" --headers "Content-Type=application/json" --body "{
  \"api\": {\"preAuthorizedApplications\": [{\"appId\": \"$AZURE_CLI_APP_ID\", \"delegatedPermissionIds\": [\"$SCOPE_ID\"]}]}
}"

if ! az ad sp show --id "$APP_ID" >/dev/null 2>&1; then
  echo "Creating service principal..."
  az ad sp create --id "$APP_ID" >/dev/null
fi

if [[ -f "$REPO_ROOT/.env" ]]; then
  echo ".env already exists; not overwriting. Values to use:"
  echo "  ENTRA_TENANT_ID=$TENANT_ID"
  echo "  ENTRA_CLIENT_ID=$APP_ID"
else
  sed -e "s|^ENTRA_TENANT_ID=.*|ENTRA_TENANT_ID=$TENANT_ID|" \
      -e "s|^ENTRA_CLIENT_ID=.*|ENTRA_CLIENT_ID=$APP_ID|" \
      -e "s|^PUBLIC_BASE_URL=.*|PUBLIC_BASE_URL=$BASE_URL|" \
      -e "s|^SESSION_SECRET=.*|SESSION_SECRET=$(openssl rand -base64 32 | tr -d '\n')|" \
      "$REPO_ROOT/.env.example" > "$REPO_ROOT/.env"
  echo "Wrote $REPO_ROOT/.env"
fi

echo
echo "Done. Next:"
echo "  az login --tenant $TENANT_ID --scope api://$APP_ID/mcp.access --allow-no-subscriptions"
echo "  docker compose up -d --build"
echo "  scripts/smoke-test.sh"
