#!/usr/bin/env bash
# Print an Entra ID access token for the MCP server, using the Azure CLI's sign-in.
set -euo pipefail
source "$(dirname "$0")/_env.sh"
command -v az >/dev/null || { echo "Azure CLI (az) not found. Install: brew install azure-cli" >&2; exit 1; }
if ! az account get-access-token --tenant "$ENTRA_TENANT_ID" --scope "$SCOPE" --query accessToken -o tsv 2>/tmp/jit-az-err; then
  cat /tmp/jit-az-err >&2
  echo >&2
  echo "Sign in first:  az login --tenant $ENTRA_TENANT_ID --scope $SCOPE --allow-no-subscriptions" >&2
  exit 1
fi
