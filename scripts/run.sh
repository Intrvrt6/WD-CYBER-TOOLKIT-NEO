#!/usr/bin/env bash
# WD CYBER TOOLKIT NEO - start the platform.
#
# Prints the URLs a client can actually use. On Android this matters: the phone
# reaches its own console at 127.0.0.1, while a laptop on the same Wi-Fi needs
# the LAN address. Both are shown, so neither has to be guessed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

HOST="${WD_HOST:-127.0.0.1}"
PORT="${WD_PORT:-8000}"
export WD_HOST="$HOST" WD_PORT="$PORT"

if [ -f .env ]; then
  echo "loading .env"
fi

echo "============================================================="
echo " WD CYBER TOOLKIT NEO"

# Report the phone-visible addresses, not just the bind address. The helper is
# the same code path the API uses, so what is printed here and what
# /api/network returns can never drift apart.
PLATFORM_INFO="$(python3 - <<'PY' 2>/dev/null || true
import sys
sys.path.insert(0, '.')
try:
    from backend import platform_utils as P
except Exception:
    sys.exit(0)
import os
port = int(os.environ.get("WD_PORT", "8000"))
print("platform:" + P.platform_label())
for u in P.lan_urls(port):
    print("url:" + u)
PY
)"

PLATFORM_LABEL="$(printf '%s\n' "$PLATFORM_INFO" | sed -n 's/^platform://p' | head -1)"
[ -n "$PLATFORM_LABEL" ] && echo " platform: ${PLATFORM_LABEL}"

if printf '%s\n' "$PLATFORM_INFO" | grep -q '^url:'; then
  FIRST_URL="$(printf '%s\n' "$PLATFORM_INFO" | sed -n 's/^url://p' | head -1)"
  echo " this device : ${FIRST_URL}  <-- open here (or point the APK at this)"
  if [ "$HOST" = "0.0.0.0" ] || [ "$HOST" = "::" ]; then
    while IFS= read -r line; do
      url="${line#url:}"
      [ "$url" = "$FIRST_URL" ] || echo " LAN        : ${url}  <-- trusted network only"
    done <<< "$(printf '%s\n' "$PLATFORM_INFO" | grep '^url:')"
  else
    echo " LAN access : disabled (set WD_HOST=0.0.0.0 only when intentionally exposing the console)"
  fi
else
  echo " http://${HOST}:${PORT}  (docs: /api/docs)"
fi

echo " API docs   : /api/docs"
echo "============================================================="

case "$PLATFORM_LABEL" in
  termux|android)
    echo " Tip: keep the server alive with 'termux-wake-lock' in another session."
    ;;
esac

# Bootstrap secrets are written to the protected one-time file; never log them.
exec python3 -m uvicorn backend.main:app --host "$HOST" --port "$PORT" --log-level info
