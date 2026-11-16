#!/usr/bin/env bash
# WD CYBER TOOLKIT NEO - installer for Linux / Kali / WSL / Termux (Android).
# Idempotent: re-running upgrades Python deps and re-checks external tools.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "=== WD CYBER TOOLKIT NEO - install ==="
echo "root: $ROOT"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3.10+ first." >&2
  exit 1
fi
"$PY" - <<'EOF'
import sys
if sys.version_info < (3, 10):
    sys.exit("ERROR: Python 3.10+ required, found %s" % sys.version.split()[0])
print("python:", sys.version.split()[0])
EOF

# ---------------------------------------------------------------- pip deps --
# A venv is preferred; --system-site-packages keeps distro-provided security
# tooling imports (e.g. yara/scapy) available without duplicating them.
if [ ! -d .venv ]; then
  echo "creating virtual environment .venv"
  "$PY" -m venv --system-site-packages .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
pip install -r requirements.txt

# -------------------------------------------------------------- OS tooling --
missing=()
for t in nmap tshark tcpdump arping candump dig whois curl openssl yara jq \
         subfinder httpx naabu nuclei katana dnsx tlsx ffuf sqlmap nikto; do
  command -v "$t" >/dev/null 2>&1 || missing+=("$t")
 done

if [ ${#missing[@]} -gt 0 ]; then
  echo
expect_os_pkgs="nmap tshark tcpdump iputils-arping can-utils dnsutils whois curl openssl yara jq nikto"
  echo "missing external tools: ${missing[*]}"
  echo "Install them with your package manager ('$expect_os_pkgs')."
  if command -v apt-get >/dev/null 2>&1; then
    echo "On Debian/Ubuntu/Kali:  sudo apt-get install -y $expect_os_pkgs"
  elif command -v pkg >/dev/null 2>&1; then
    echo "On Termux:  pkg install -y nmap tshark tcpdump iputils can-utils dnsutils whois curl openssl yara jq"
  fi
  echo "ProjectDiscovery tools:  go install github.com/projectdiscovery/{subfinder,httpx,naabu,nuclei,katana,dnsx,tlsx}/v2/cmd/<tool>@latest"
  echo "(missing tools are reported in the Capabilities view; the platform runs either way)"
fi

# ------------------------------------------------------------------- ready --
chmod +x scripts/*.sh 2>/dev/null || true
"$PY" - <<'EOF'
import sys
sys.path.insert(0, '.')
from backend import config, database, capabilities
config.ensure_dirs()
database.init_db()
print("database ready:", config.DATABASE_URL)
caps = capabilities.report()
present = [k for k, v in caps["cli_tools"].items() if v["present"]]
print(f"cli tools present: {len(present)}")
mods = [k for k, v in caps["python_modules"].items() if v["present"]]
print(f"python modules present: {len(mods)}/{len(caps['python_modules'])}")
EOF

echo
echo "Install complete."
echo "Start the platform:   ./scripts/run.sh"
echo "Run the test suite:   ./scripts/test.sh"
echo "Bootstrap credentials are created on first boot and written to database/bootstrap_credentials.txt"
