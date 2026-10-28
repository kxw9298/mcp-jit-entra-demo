#!/usr/bin/env bash
# Start Claude Code in this repo with a fresh Entra ID token for the jit-mcp server.
# The token goes into MCP_JIT_TOKEN, which .mcp.json expands into the Authorization header.
# Tokens last about an hour; restart this script to refresh.
set -euo pipefail
cd "$(dirname "$0")/.."
MCP_JIT_TOKEN="$(scripts/get-token.sh)"
export MCP_JIT_TOKEN
exec claude "$@"
