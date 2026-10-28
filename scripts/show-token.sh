#!/usr/bin/env bash
# Decode the access token Claude Code will send, so you can see aud / scp / oid / exp.
set -euo pipefail
TOKEN="$("$(dirname "$0")/get-token.sh")"
python3 - "$TOKEN" <<'PY'
import base64, json, sys, datetime
payload = sys.argv[1].split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
keep = ["iss", "aud", "tid", "oid", "name", "upn", "unique_name", "preferred_username", "scp", "azp", "appid", "ver", "exp"]
for k in keep:
    if k in claims:
        v = claims[k]
        if k == "exp":
            v = f"{v} ({datetime.datetime.fromtimestamp(v).isoformat()})"
        print(f"{k:20} {v}")
PY
