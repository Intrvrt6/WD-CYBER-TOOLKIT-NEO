#!/usr/bin/env bash
# WD CYBER TOOLKIT NEO - start the platform.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

HOST="${WD_HOST:-0.0.0.0}"
PORT="${WD_PORT:-8000}"

if [ -f .env ]; then
  echo "loading .env"
fi

echo "============================================================="
echo " WD CYBER TOOLKIT NEO"
echo " http://${HOST}:${PORT}  (docs: /api/docs)"
echo "============================================================="

# Bootstrap secrets are printed by the app on first boot only.
exec python3 -m uvicorn backend.main:app --host "$HOST" --port "$PORT" --log-level info
