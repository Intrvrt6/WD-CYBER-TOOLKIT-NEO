#!/usr/bin/env bash
# WD CYBER TOOLKIT NEO - end-to-end demo.
#
# Boots a throwaway instance, performs the full two-stage login, registers scope,
# authorizes a test, executes a real assessment, then prints findings and writes
# a PDF report. Nothing is mocked: the assessment really runs against the target
# you pass (default: the bundled local lab).
#
# Usage:
#   ./scripts/demo.sh                       # network pentest of the loopback host
#   ./scripts/demo.sh testssl.sh            # network pentest of a real host in scope
#   MODULE=scada_ics ./scripts/demo.sh      # lab-mode ICS assessment
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT"
[ -d .venv ] && source .venv/bin/activate

TARGET="${1:-127.0.0.1}"
MODULE="${MODULE:-network}"
PORT="${WD_DEMO_PORT:-8099}"
API="http://127.0.0.1:${PORT}"
CRED="$ROOT/database/bootstrap_credentials.txt"

case "$MODULE" in
  network)         TEMPLATE=network_pentest; MODE=live; TPARAM='{"capture_seconds":5}' ;;
  mitm)            TEMPLATE=mitm_pentest;    MODE=live; TPARAM='{}' ;;
  scada_ics)       TEMPLATE=scada_pentest;   MODE=lab;  TPARAM='{}' ; TARGET="modbus://127.0.0.1:5020" ;;
  automotive_can)  TEMPLATE=can_pentest;     MODE=lab;  TPARAM='{}' ; TARGET="can:wdcan0" ;;
  threat_intelligence) TEMPLATE=ioc_pentest; MODE=live; TPARAM="{\"iocs\":[\"203.0.113.45\",\"example.com\"]}" ;;
  webapp)          TEMPLATE=webapp_pentest;  MODE=live; TPARAM='{}' ;;
  mobile_security) TEMPLATE=mobile_pentest;  MODE=live; TPARAM='{}' ;;
  social_engineering) TEMPLATE=social_pentest; MODE=live; TPARAM='{}' ;;
  physical_security)  TEMPLATE=physical_pentest; MODE=live; TPARAM='{}' ;;
  hardware_security)  TEMPLATE=hardware_pentest; MODE=live; TPARAM='{}' ;;

  *) echo "unknown MODULE=$MODULE"; exit 1 ;;
esac

echo "=== starting demo server on :$PORT ==="
WD_PORT="$PORT" setsid nohup python3 -m uvicorn backend.main:app --host 127.0.0.1 --port "$PORT" \
  > /tmp/wd_demo_$PORT.log 2>&1 < /dev/null &
SRV=$!
cleanup() { kill "$SRV" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 40); do
  curl -sf --max-time 2 "$API/api/health" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf --max-time 5 "$API/api/health" >/dev/null || { echo 'server did not start'; tail -20 /tmp/wd_demo_$PORT.log; exit 1; }

U=$(grep 'Operator username'  "$CRED" | awk -F': ' '{print $2}')
P=$(grep 'Operator password'  "$CRED" | awk -F': ' '{print $2}')
N=$(grep 'Stage-2 PIN'       "$CRED" | awk -F': ' '{print $2}')
S=$(grep 'Stage-1 WD shortcut' "$CRED" | awk -F': ' '{print $2}')

echo "=== 1/6 stage 1 ==="
TOKEN=$(python3 - "$API" "$U" "$P" "$S" <<'PY'
import json, sys, urllib.request
api, u, p, s = sys.argv[1:5]
req = urllib.request.Request(api + "/api/auth/stage1",
    data=json.dumps({"username": u, "password": p, "shortcut": s}).encode(),
    headers={"content-type": "application/json"})
print(json.load(urllib.request.urlopen(req, timeout=30))["token"])
PY
)
echo "token acquired"
H="authorization: Bearer $TOKEN"

echo "=== 2/6 stage 2 ==="
curl -sS --max-time 30 -X POST "$API/api/auth/stage2" -H "$H" -H 'content-type: application/json' \
  -d "{\"pin\":\"$N\"}" | python3 -c 'import json,sys; d=json.load(sys.stdin); print("stage", d["stage"])'

echo "=== 3/6 register scope: $TARGET ==="
curl -sS --max-time 30 -X POST "$API/api/scope" -H "$H" -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"target": sys.argv[1], "description": "demo target"}))' "$TARGET")" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("scope", d["target"], d["target_type"])'

echo "=== 4/6 authorize ==="
AUTHZ=$(curl -sS --max-time 30 -X POST "$API/api/authorizations" -H "$H" -H 'content-type: application/json' \
  -d "$(python3 -c 'import json,sys; print(json.dumps({"targets":[sys.argv[1]],"ttl_minutes":30,"intended_test":"demo assessment"}))' "$TARGET")" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "authorization $AUTHZ"

echo "=== 5/6 create + run: $TEMPLATE ($MODE) ==="
ASID=$(python3 - "$API" "$TOKEN" "$TEMPLATE" "$TARGET" "$MODE" "$TPARAM" <<'PY'
import json, sys, urllib.request
api, token, tpl, target, mode, params = sys.argv[1:7]
body = json.dumps({"template": tpl, "targets": [target], "mode": mode,
                   "intensity": "light", "params": json.loads(params)}).encode()
req = urllib.request.Request(api + "/api/assessments", data=body,
    headers={"content-type": "application/json", "authorization": "Bearer " + token})
print(json.load(urllib.request.urlopen(req, timeout=30))["id"])
PY
)
JOB=$(python3 - "$API" "$TOKEN" "$ASID" "$AUTHZ" <<'PY'
import json, sys, urllib.request
api, token, asid, authz = sys.argv[1:5]
body = json.dumps({"authz_id": authz, "confirm": True}).encode()
req = urllib.request.Request(api + f"/api/assessments/{asid}/run", data=body,
    headers={"content-type": "application/json", "authorization": "Bearer " + token})
print(json.load(urllib.request.urlopen(req, timeout=30))["job_id"])
PY
)
echo "assessment $ASID / job $JOB"

for i in $(seq 1 90); do
  sleep 2
  ST=$(curl -sS --max-time 10 "$API/api/jobs/$JOB" -H "$H" \
       | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], d["progress"])')
  echo "  poll $i: $ST"
  case "$ST" in completed*|failed*|aborted*) break ;; esac
done

echo "=== 6/6 findings ==="
curl -sS --max-time 20 "$API/api/assessments/$ASID/findings" -H "$H" \
  | python3 -c 'import json,sys
for f in json.load(sys.stdin)["findings"]:
    print(f"  {f[chr(99)+chr(104)+chr(101)+chr(99)+chr(107)+chr(95)+chr(105)+chr(100)]:10s} {f[chr(115)+chr(101)+chr(118)+chr(101)+chr(114)+chr(105)+chr(116)+chr(121)]:8s} {f[chr(101)+chr(118)+chr(105)+chr(100)+chr(101)+chr(110)+chr(99)+chr(101)+chr(95)+chr(115)+chr(111)+chr(117)+chr(114)+chr(99)+chr(101)]:11s} {f[chr(116)+chr(105)+chr(116)+chr(108)+chr(101)][:60]}")'

OUT="$ROOT/reports/demo_${MODULE}.pdf"
curl -sS --max-time 120 "$API/api/assessments/$ASID/report?fmt=pdf&lang=en" -H "$H" -o "$OUT"
echo "report: $OUT ($(stat -c%s "$OUT" 2>/dev/null || echo 0) bytes)"

echo "=== audit chain ==="
curl -sS --max-time 20 "$API/api/audit/verify" -H "$H"
echo
