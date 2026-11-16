# Termux / Android

Running WD CYBER TOOLKIT NEO **on the phone itself**, and connecting the Android
APK to that console.

There are two independent ways to use the platform from Android:

| Way | What runs where | Use it when |
|---|---|---|
| **Termux console** | Full Python backend + web UI, inside Termux on the phone | You want the real platform (all 10 engines) on the device, reachable from its own browser |
| **APK client** | Thin Java client on the phone, backend anywhere | You want a native app; point it at a Termux console (same phone) or a LAN/desktop console |
| **Both together** | APK → `http://127.0.0.1:8000` → Termux console on the same phone | Native app driving the full platform, no PC involved |

---

## 1. Install on Termux

```bash
pkg install -y git
cd ~
git clone https://github.com/Intrvrt6/WD-CYBER-TOOLKIT-NEO.git
cd WD-CYBER-TOOLKIT-NEO
bash scripts/termux.sh
```

One command does everything: installs packages, installs the core Python set,
initialises the database, takes a wake lock and starts the console. It prints the
addresses to use:

```
=============================================================
 WD CYBER TOOLKIT NEO
 platform: termux
 this device : http://127.0.0.1:8000  <-- open here (or point the APK at this)
 LAN        : http://192.168.1.42:8000  <-- other devices on the same network
=============================================================
```

Then open `http://127.0.0.1:8000` **in the phone's browser** (Chrome/Firefox on the
same device can reach the phone's own loopback).

### Other modes

```bash
bash scripts/termux.sh --check     # diagnose only, change nothing
bash scripts/termux.sh --install   # install without starting
bash scripts/termux.sh --run       # start only (already installed)
bash scripts/termux.sh --help
```

`scripts/install.sh` also works — it detects Termux and hands over to `termux.sh`
automatically.

---

## 2. What is different on Android (and why it works anyway)

Android is not a small Linux. Four real differences are handled explicitly, so the
platform does not silently degrade:

### 2.1 No `iproute2` — interface detection uses a fallback chain

Termux ships without `ip` or `ss`. A naive `ip -br addr` returns nothing, and the
UI used to show **zero interfaces** with no explanation.

`backend/platform_utils.py` now walks a fallback chain and reports which one it used:

```
ip -br addr  ->  ip addr show  ->  ifconfig -a  ->  psutil  ->  ioctl(SIOCGIFADDR)
```

The last link needs **no external binary at all** — it is a plain syscall
(`if_indextoname` + `SIOCGIFADDR`), so a phone can always report its own address.

Verify on the device:

```bash
python3 -c "from backend import platform_utils as P; print(P.interface_source()); print(P.interfaces())"
```

### 2.2 No venv — packages install into the Termux Python

`python3 -m venv` is unreliable on Termux, so `termux.sh` installs directly and
pulls `clang`/`make`/`pkg-config` so `argon2-cffi` and `cryptography` can build.

### 2.3 Compile-heavy modules are optional, not mandatory

`requirements.txt` pins `scapy`, `asyncua`, `pymodbus`, `python-can` and
`yara-python`, which either fail to build or are pointless on a phone.
Termux uses **`requirements-core.txt`** — the subset that installs cleanly — and the
optional modules are attempted afterwards, best effort.

A module whose dependency is missing says so honestly (`source: unavailable` with
the reason) instead of pretending it ran.

### 2.4 The phone must stay awake

Android suspends background processes when the screen turns off. `termux.sh` takes a
`termux-wake-lock`. Keep it if you want the console to survive:

```bash
termux-wake-lock        # acquire
exit                    # lock persists for the session
termux-wake-unlock      # release when done
```

Install `termux-api` (`pkg install termux-api`) for this to work.

---

## 3. Live capture needs root

Reading packets on Android requires `CAP_NET_RAW`. Termux can borrow root on a
rooted device with `tsu`:

```bash
pkg install tsu
sudo tsu        # enter a root shell
bash scripts/termux.sh --run
```

Without root:

- `lab` mode works fully (bundled Modbus/OPC UA/CAN simulators need no privileges).
- Network/web/mobile/hardware/social modules work (they use ordinary sockets).
- Live packet capture and ARP checks report `unavailable` with the reason.

---

## 4. Connect the APK

The APK ships with the correct default: **`http://127.0.0.1:8000`** — the console on
the same phone. (Older builds defaulted to `10.0.2.2`, which is the *emulator's* host
alias and is dead on real hardware — that was a genuine bug, now fixed and covered by
a regression test.)

### Install the APK

```bash
# copy to the phone, then:
pkg install x11-repo 2>/dev/null; pkg install -y android-tools
adb install -r wd-neo.apk
```

Or open the `.apk` file with any file manager and allow install from unknown sources.

### Point it at a console

**Automatic** — press **DETECT** on the login screen. The app probes
`127.0.0.1`, then the emulator alias (emulators only), then asks any console it finds
`GET /api/network` for the addresses it advertises, and saves the first one that
actually answers `/api/health`. Nothing is assumed to be up; if nothing answers it
says so, including the port it tried.

**Manual** — type the address in the *server* field:

| Console runs on | Address to use |
|---|---|
| The same phone (Termux) | `http://127.0.0.1:8000` |
| Another phone / PC on the LAN | `http://192.168.1.42:8000` (see `LAN` line) |
| Android emulator, console on host | `http://10.0.2.2:8000` |
| Behind a reverse proxy | `https://wd.example.com` |

Then **CONNECT** → stage 1 (WD shortcut + password) → stage 2 (PIN).

### Discover the URL from any shell

```bash
curl -s http://127.0.0.1:8000/api/network | python3 -m json.tool
```

```json
{
  "platform": "termux",
  "is_termux": true,
  "port": 8000,
  "primary_lan_ip": "192.168.1.42",
  "urls": ["http://127.0.0.1:8000", "http://192.168.1.42:8000"],
  "on_device_url": "http://127.0.0.1:8000",
  "lan_url": "http://192.168.1.42:8000",
  "interface_source": "psutil",
  "has_iproute2": false
}
```

This endpoint is intentionally unauthenticated: a client must learn the address
**before** it can log in. It exposes addressing facts only — no scope, findings or
secrets.

---

## 5. First login on the phone

On first boot the console generates credentials once and writes them to
`database/bootstrap_credentials.txt`:

```bash
cat database/bootstrap_credentials.txt
```

Or provision them up front instead:

```bash
export WD_ADMIN_USER=WD-OPERATOR-01
export WD_ADMIN_PASSWORD='Your-Strong-Pass-1'
export WD_ADMIN_PIN=42424242
export WD_SHORTCUT=WD-XXXXXXXXXXXXX
bash scripts/termux.sh --run
```

Delete `bootstrap_credentials.txt` after storing the values.

---

## 6. Recommended phone setup

```bash
# keep it alive across screen-off
pkg install termux-api && termux-wake-lock

# survive Termux being closed
termux-services 2>/dev/null || true

# run on boot (Termux:Boot app required)
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/wd-neo.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/sh
termux-wake-lock
cd ~/WD-CYBER-TOOLKIT-NEO && bash scripts/termux.sh --run
EOF
chmod +x ~/.termux/boot/wd-neo.sh
```

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `iproute2 reported absent` | Normal on Termux | Nothing to do — the fallback handles it |
| Interfaces list is empty | No fallback worked | Run `python3 -c "from backend import platform_utils as P; print(P._rows_from_ioctl())"`; report the output |
| `argon2-cffi` fails to build | Missing toolchain | `pkg install clang make pkg-config` then re-run |
| `cryptography` fails to build | Same, or no rust | `pkg install rust` (or `pkg install python-cryptography`) |
| Console stops when screen off | No wake lock | `pkg install termux-api && termux-wake-lock` |
| APK says *no console on 127.0.0.1:8000* | Console not running on the phone | `bash scripts/termux.sh --run` |
| APK can't reach another device | Different Wi-Fi / AP isolation | Use the `LAN` URL printed at startup; disable AP isolation |
| Live capture says `unavailable` | No root | `pkg install tsu` and run as root, or use `lab` mode |
| Port 8000 already in use | Previous instance running | `pkill -f uvicorn` then restart |

Full diagnostics in one shot:

```bash
bash scripts/termux.sh --check
python3 scripts/termux_proof.py     # 30 end-to-end checks
```

---

## 8. How this is verified

There is no Android device or emulator in the build environment (no KVM), so Termux
behaviour is proven by **simulating its environment** — hiding `ip`/`ss`/`ifconfig`
from `PATH` and setting the Android markers — then asserting the whole stack works:

```
$ python3 scripts/termux_proof.py
1. platform detection ................ 4/4
2. interfaces without iproute2 ....... 4/4    (3 real rows via psutil)
3. reachable URLs .................... 4/4
4. API boot, login, assessment ....... 18/18  (10 engines, audit valid, PDF 10.7 KB)
RESULT: 30 passed, 0 failed
```

Plus 30 unit tests in `tests/test_termux_android.py` covering detection, the
fallback chain, LAN-URL shape, the requirement split, script syntax, and the APK
default/detect regressions.

**Honest limitation:** real-hardware behaviour (actual Termux `pkg` resolution, a
real phone's interface names, wake-lock under OEM battery savers) can only be
confirmed on a device. The interfaces are implemented and the simulated path is
proven; a device run is the remaining step.
