#!/data/data/com.termux/files/usr/bin/bash
# WD CYBER TOOLKIT NEO - one-command installer for Termux (Android).
#
#   bash scripts/termux.sh            install and start the console
#   bash scripts/termux.sh --install  install only
#   bash scripts/termux.sh --check    diagnose the environment, change nothing
#
# Idempotent: re-running upgrades packages and restarts the server cleanly.
#
# Why this script exists instead of reusing scripts/install.sh: Termux differs in
# four ways that break the generic installer.
#   1. There is no apt; packages come from `pkg`.
#   2. C extensions (argon2-cffi, cryptography) need clang + python-dev, which are
#      not installed by default.
#   3. `python3 -m venv` often fails on Termux; a plain pip install into the
#      Termux python is the reliable path.
#   4. Compile-heavy optional deps (yara, asyncua, pymodbus, python-can) either
#      fail to build or are pointless on a phone, so a core-only requirement set
#      is used and the affected modules report `unavailable` honestly.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$ROOT" || exit 1

MODE="--install-and-run"
case "${1:-}" in
  --install|-i) MODE="--install" ;;
  --check|-c)   MODE="--check" ;;
  --run|-r)     MODE="--run" ;;
  --help|-h)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  "") ;;
  *) echo "unknown option: $1 (try --help)"; exit 2 ;;
esac

OK=0; WARN=0; FAIL=0
say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ ok ] %s\n' "$*"; OK=$((OK+1)); }
warn() { printf '  [warn] %s\n' "$*"; WARN=$((WARN+1)); }
fail() { printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }
head1() { printf '\n=== %s ===\n' "$*"; }

# ------------------------------------------------------------------ detect --
head1 "environment"
if [ -z "${TERMUX_VERSION:-}" ] && [ ! -d /data/data/com.termux/files/usr ]; then
  warn "this does not look like Termux (TERMUX_VERSION unset)."
  warn "on Debian/Ubuntu/Kali use ./scripts/install.sh instead."
else
  ok "Termux ${TERMUX_VERSION:-detected} on $(uname -m)"
fi
say "  prefix      : ${PREFIX:-unset}"
say "  python      : $(python3 --version 2>&1 | head -1)"
say "  repo        : $ROOT"

if [ "$MODE" = "--check" ]; then
  head1 "capability check (no changes)"
  python3 - <<'PY' 2>/dev/null || fail "could not import the backend"
import sys
sys.path.insert(0, '.')
from backend import platform_utils as P
print(f"  platform      : {P.platform_label()}")
print(f"  interface src : {P.interface_source()}")
print(f"  iproute2      : {P.has_iproute2()}")
print(f"  primary LAN IP: {P.primary_lan_ip()}")
print(f"  reachable URLs: {', '.join(P.lan_urls())}")
for r in P.interfaces():
    print(f"  iface {r['name']:<10} {r['state']:<5} {r['addresses']}")
PY
  say ""
  exit 0
fi

# ---------------------------------------------------------------- packages --
if [ "$MODE" != "--run" ]; then
  head1 "installing Termux packages"
  if ! command -v pkg >/dev/null 2>&1; then
    fail "pkg not found - this is not Termux"
  else
    export DEBIAN_FRONTEND=noninteractive
    # python + build chain are mandatory for argon2-cffi / cryptography wheels.
    CORE_PKGS="python clang make pkg-config openssl libffi rust binutils"
    # Useful but optional: the platform runs without every one of these.
    OPT_PKGS="nmap dnsutils curl jq git nano tsu termux-api"

    say "  upgrading package index (this can take a minute)"
    if yes | pkg upgrade -y >/dev/null 2>&1; then ok "package index upgraded"
    else warn "pkg upgrade reported a problem (continuing)"; fi

    for p in $CORE_PKGS; do
      if pkg install -y "$p" >/dev/null 2>&1; then ok "core: $p"
      else fail "core: $p could not be installed"; fi
    done
    for p in $OPT_PKGS; do
      if pkg install -y "$p" >/dev/null 2>&1; then ok "optional: $p"
      else warn "optional: $p unavailable in this repo"; fi
    done
  fi

  # ------------------------------------------------------------- pip deps --
  head1 "installing Python dependencies (core set)"
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || warn "pip self-upgrade failed (continuing)"
  if python3 -m pip install -r requirements-core.txt; then
    ok "requirements-core.txt installed"
  else
    fail "core requirements failed to install"
    say "  retrying one package at a time to find the culprit..."
    while IFS= read -r req; do
      case "$req" in ''|'#'*) continue ;; esac
      pkgname="${req%%[<>=]*}"
      if python3 -m pip install "$req" >/dev/null 2>&1; then ok "$pkgname"
      else fail "$pkgname"; fi
    done < requirements-core.txt
  fi

  # Optional heavy modules, best-effort: each one that installs enables a module.
  head1 "optional modules (best effort)"
  for spec in "psutil" "python-can" "pymodbus" "scapy"; do
    if python3 -c "import importlib,sys; importlib.import_module('${spec//-/_}')" >/dev/null 2>&1; then
      ok "$spec already present"
    elif python3 -m pip install "$spec" >/dev/null 2>&1; then ok "$spec installed"
    else warn "$spec skipped (module will report unavailable)"; fi
  done
fi

# --------------------------------------------------------------- database --
head1 "initialising storage"
if python3 - <<'PY'
import sys
sys.path.insert(0, '.')
from backend import config, database
config.ensure_dirs()
database.init_db()
print(f"  database: {config.DATABASE_URL}")
print(f"  evidence: {config.EVIDENCE_DIR}")
print(f"  reports : {config.REPORT_DIR}")
PY
then ok "database ready"
else fail "database initialisation failed"; fi

chmod +x scripts/*.sh 2>/dev/null || true

# ------------------------------------------------------------- wake lock --
head1 "Android specifics"
if command -v termux-wake-lock >/dev/null 2>&1; then
  termux-wake-lock 2>/dev/null && ok "wake lock acquired (server survives screen-off)" \
    || warn "wake lock failed (server may pause when the screen turns off)"
else
  warn "termux-api missing: install it and run 'termux-wake-lock' to keep the server alive"
fi

if command -v tsu >/dev/null 2>&1; then
  ok "tsu present: 'sudo tsu' enables live packet capture"
else
  warn "tsu absent: live capture needs root, lab mode works without it"
fi

# ------------------------------------------------------------------ report --
head1 "summary"
i=0
say "  checks passed : $OK"
[ "$WARN" -gt 0 ] && say "  warnings      : $WARN"
[ "$FAIL" -gt 0 ] && say "  failures      : $FAIL"

PORT="${WD_PORT:-8000}"
if python3 -c "
import sys
sys.path.insert(0, '.')
from backend import platform_utils as P
print(P.lan_urls(int('${PORT}'))[0])
" >/tmp/wd_first_url 2>/dev/null; then
  FIRST_URL="$(cat /tmp/wd_first_url)"
else
  FIRST_URL="http://127.0.0.1:${PORT}"
fi

say ""
say "  Open on this phone : $FIRST_URL"
LANIP="$(python3 -c "import sys;sys.path.insert(0,'.');from backend import platform_utils as P;print(P.primary_lan_ip() or '')" 2>/dev/null)"
[ -n "$LANIP" ] && say "  Open from the LAN  : http://${LANIP}:${PORT}"
say "  APK server field   : $FIRST_URL"

if [ "$FAIL" -gt 0 ]; then
  say ""
  say "  $FAIL check(s) failed - the console may still start; see the list above."
fi

if [ "$MODE" = "--install" ]; then
  say ""
  say "  Start it with:  bash scripts/termux.sh --run"
  exit 0
fi

if [ "$MODE" = "--run" ] || [ "$MODE" = "--install-and-run" ]; then
  head1 "starting the console"
  say "  Press CTRL+C to stop."
  say ""
  export WD_HOST="${WD_HOST:-0.0.0.0}"
  export WD_PORT="$PORT"
  exec python3 -m uvicorn backend.main:app --host "$WD_HOST" --port "$WD_PORT" --log-level info
fi
