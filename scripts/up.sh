#!/usr/bin/env bash
# One-shot local setup: create .env (if missing), build the image, start the container, wait until healthy.
#
#   scripts/up.sh <tenant-id> <client-id>      # first run
#   scripts/up.sh                              # later runs (uses the existing .env)
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then
  if [[ $# -lt 2 ]]; then
    echo "No .env yet. Run: scripts/up.sh <ENTRA_TENANT_ID> <ENTRA_CLIENT_ID>" >&2
    exit 1
  fi
  cat > .env <<EOF
ENTRA_TENANT_ID=$1
ENTRA_CLIENT_ID=$2
PUBLIC_BASE_URL=http://localhost:8000
SESSION_SECRET=$(openssl rand -base64 32 | tr -d '\n')
LOG_LEVEL=INFO
EOF
  echo "Wrote .env"
fi

command -v docker >/dev/null || { echo "Docker not found. Start Docker Desktop first." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker isn't running. Open Docker Desktop and wait for it to start." >&2; exit 1; }

echo "Building and starting jit-mcp..."
docker compose up -d --build

echo -n "Waiting for the server"
for _ in $(seq 1 30); do
  if curl -fsS http://localhost:8000/healthz >/dev/null 2>&1; then
    echo " ok"
    docker compose ps
    echo
    echo "Server is up: http://localhost:8000/jit"
    echo "Next: scripts/smoke-test.sh   then   scripts/claude-jit.sh"
    exit 0
  fi
  echo -n "."; sleep 2
done
echo
echo "Server did not become healthy. Logs:" >&2
docker compose logs --tail 60 >&2
exit 1
