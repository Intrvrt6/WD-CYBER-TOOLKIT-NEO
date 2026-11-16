#!/usr/bin/env bash
# Run the JVM core harness against a live WD NEO backend.
# 
# This exercises the exact Json/HttpClient/WdApi classes that are packaged into
# the APK, over the real HTTP API - the emulator substitute.
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

BASE="${1:-http://127.0.0.1:8000}"
CREDS="${CREDS_FILE:-/tmp/creds.json}"

[ -f "$CREDS" ] || { echo "missing credentials file: $CREDS" >&2; exit 1; }

mapfile -t FIELDS < <(python3 - "$CREDS" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
for k in ("user", "pass", "pin", "shortcut"):
    print(c[k])
PY
)

rm -rf build/harness
mkdir -p build/harness
javac -source 17 -target 17 -Xlint:-options -encoding UTF-8 \
  -d build/harness \
  $(find src/sh/testssl/wdneo/core -name '*.java') \
  harness/harness/CoreHarness.java

echo "=== core harness against $BASE ==="
java -cp build/harness harness.CoreHarness \
  "$BASE" "${FIELDS[0]}" "${FIELDS[1]}" "${FIELDS[2]}" "${FIELDS[3]}"
