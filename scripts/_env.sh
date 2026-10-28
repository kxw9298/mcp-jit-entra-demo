# Shared helper: load .env and work out the scope to request.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -f "$REPO_ROOT/.env" ]]; then
  echo "Missing $REPO_ROOT/.env. Copy .env.example to .env and fill in the Entra IDs." >&2
  exit 1
fi
set -a; source "$REPO_ROOT/.env"; set +a
APP_ID_URI="${ENTRA_APP_ID_URI:-api://$ENTRA_CLIENT_ID}"
SCOPE="$APP_ID_URI/mcp.access"
