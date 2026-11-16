#!/usr/bin/env bash
# WD CYBER TOOLKIT NEO - run the test suite.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"

if [ -d .venv ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

echo "=== WD CYBER TOOLKIT NEO - test suite ==="
exec python3 -m pytest tests/ "$@"
