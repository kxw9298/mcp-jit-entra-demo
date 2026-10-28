#!/usr/bin/env bash
# Check the running server: health, OAuth metadata, 401 without a token, tools/list with a token.
set -euo pipefail
source "$(dirname "$0")/_env.sh"
BASE="${PUBLIC_BASE_URL:-http://localhost:8000}"
echo "== health";               curl -fsS "$BASE/healthz"; echo
echo "== protected resource metadata"; curl -fsS "$BASE/.well-known/oauth-protected-resource/mcp"; echo
echo "== no token (expect 401)"
curl -s -o /dev/null -D - -X POST "$BASE/mcp" -H 'content-type: application/json' -d '{}' | grep -iE "^HTTP|www-authenticate"
echo "== with token: tools/list"
TOKEN="$("$(dirname "$0")/get-token.sh")"
curl -fsS -X POST "$BASE/mcp" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' -H 'mcp-protocol-version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  | python3 -c 'import json,sys; print("tools:", ", ".join(t["name"] for t in json.load(sys.stdin)["result"]["tools"]))'
