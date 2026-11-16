"""Platform abstraction for Linux, Kali, WSL, Windows and Android/Termux.

Why this module exists
----------------------
The backend was written against GNU/Linux assumptions that simply do not hold on
Android: Termux ships no iproute2 (`ip`), no `ss`, no `/sys/class/net` guarantees
and a different set of sockets available to unprivileged processes. Calling
`ip -br addr` there returns an empty string, which used to surface in the UI as
"zero interfaces" with no explanation.

This module provides one interface-detection path with an explicit fallback
chain, so every caller gets either real data or an honest empty result with a
reason. Nothing is fabricated.

Fallback order for `interfaces()`:

    ip -br addr   ->   ip addr show   ->   ifconfig -a   ->   psutil   ->   ioctl

`ioctl(SIOCGIFCONF)` is the last resort: it is a plain syscall that works on
Termux without any external binary, so a phone can always report its own
addresses even with zero extra packages installed.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import struct
from collections.abc import Mapping
from typing import Any

from backend import runner

# ---------------------------------------------------------------------------
# Linux socket ioctl constants (Python's socket module does not expose them).
# Each is guarded by an os.name check at the point of use.
# ---------------------------------------------------------------------------
_IFNAMSIZ = 16
_SIZEOF_IFREQ = 40
_SIOCGIFCONF = 0x8912
_SIOCGIFFLAGS = 0x8913
_SIOCGIFADDR = 0x8915
_IFF_UP = 0x1

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
TERMUX_PREFIX = "/data/data/com.termux/files/usr"


def is_termux() -> bool:
    """True when running inside Termux on Android."""
    if os.environ.get("TERMUX_VERSION"):
        return True
    if os.environ.get("PREFIX", "").startswith(TERMUX_PREFIX):
        return True
    return os.path.isdir(TERMUX_PREFIX)


def is_android() -> bool:
    """True on Android, including Termux and proot/chroot environments."""
    if is_termux():
        return True
    if "android" in os.environ.get("OSTYPE", "").lower():
        return True
    try:
        with open("/system/build.prop", encoding="utf-8", errors="replace") as fh:
            return "ro.build" in fh.read(512)
    except OSError:
        return False


def is_windows() -> bool:
    return os.name == "nt"


def is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as fh:
            v = fh.read().lower()
        return "microsoft" in v or "wsl" in v
    except OSError:
        return False


def platform_label() -> str:
    """Human label used in the UI and the /api/network response."""
    if is_termux():
        return "termux"
    if is_android():
        return "android"
    if is_wsl():
        return "wsl"
    if is_windows():
        return "windows"
    return "linux"


def has_iproute2() -> bool:
    return shutil.which("ip") is not None


def has_can_utils() -> bool:
    """SocketCAN userspace tools are usually absent on Android."""
    return shutil.which("candump") is not None


# ---------------------------------------------------------------------------
# Interface enumeration
# ---------------------------------------------------------------------------
def _rows_from_ip_brief(stdout: str) -> list[dict]:
    rows = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            rows.append({"name": parts[0], "state": parts[1],
                         "addresses": [p for p in parts[2:] if p not in ("UP", "DOWN")]})
    return rows


def _rows_from_ip_addr(stdout: str) -> list[dict]:
    """Parse `ip addr show`, which also works on older/normal iproute2."""
    rows: list[dict] = []
    current: dict | None = None
    for line in stdout.splitlines():
        header = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?:\s+<([^>]*)>", line)
        if header:
            current = {
                "name": header.group(1),
                "state": "UP" if "UP" in header.group(2).split(",") else "DOWN",
                "addresses": [],
            }
            rows.append(current)
            continue
        if current is None:
            continue
        addr = re.match(r"^\s+inet6?\s+(\S+)", line)
        if addr:
            current["addresses"].append(addr.group(1))
    return rows


def _rows_from_ifconfig(stdout: str) -> list[dict]:
    rows: list[dict] = []
    current: dict | None = None
    for line in stdout.splitlines():
        head = re.match(r"^(\S+?):?\s+flags=", line) or re.match(r"^(\S+?)\s+Link encap", line)
        if head:
            name = head.group(1)
            current = {"name": name,
                       "state": "UP" if re.search(r"<[^>]*UP[^>]*>|UP\b", line) else "DOWN",
                       "addresses": []}
            rows.append(current)
            continue
        if current is None:
            continue
        inet = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
        if inet:
            current["addresses"].append(inet.group(1))
        inet6 = re.search(r"inet6 (?:addr: )?([0-9a-fA-F:]+)", line)
        if inet6:
            current["addresses"].append(inet6.group(1))
    return rows


def _rows_from_psutil() -> list[dict]:
    try:
        import psutil
    except Exception:
        return []
    rows = []
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
    except Exception:
        return []
    for name, entries in addrs.items():
        addresses = []
        for e in entries:
            if e.family in (socket.AF_INET, socket.AF_INET6):
                if e.address:
                    addresses.append(e.address)
        st = stats.get(name)
        rows.append({"name": name, "state": "UP" if (st and st.isup) else "DOWN",
                     "addresses": addresses})
    return rows


def _rows_from_ioctl() -> list[dict]:
    """Last resort: SIOCGIFADDR via a raw syscall, one interface at a time.

    Works on Termux with no external binaries at all, which is the whole point:
    an Android phone must still be able to report its own LAN address.

    Two details that are easy to get wrong (both verified against the kernel):

    * SIOCGIFCONF needs a caller-supplied output pointer inside `struct ifconf`.
      Leaving it NULL makes the kernel report the correct length but write the
      records to address 0, so every record reads back as empty.
    * `fcntl.ioctl` mutates a bytearray *in place* and returns the ioctl status
      as an int, so the data must be read back from the argument.

    This implementation therefore skips ifconf entirely and queries each
    interface directly, which is simpler and has no pointer to mismanage.
    """
    if os.name != "posix":  # pragma: no cover - non-Linux
        return []
    try:
        import ctypes
        import fcntl
    except Exception:  # pragma: no cover - non-Linux
        return []

    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except Exception:  # pragma: no cover
        return []

    names: list[str] = []
    for idx in range(1, 64):
        namebuf = ctypes.create_string_buffer(_IFNAMSIZ)
        try:
            libc.if_indextoname(idx, namebuf)
        except Exception:  # pragma: no cover
            break
        if not namebuf.value:
            continue
        names.append(namebuf.value.decode("utf-8", "replace"))

    rows: list[dict] = []
    for name in names:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError:  # pragma: no cover
            continue
        addresses: list[str] = []
        state = "UP"
        try:
            flags = bytearray(struct.pack("16s", name.encode()) +
                              b"\x00" * (_SIZEOF_IFREQ - _IFNAMSIZ))
            fcntl.ioctl(sock.fileno(), _SIOCGIFFLAGS, flags)
            # ifr_flags sits in the union right after the 16-byte name.
            ifr_flags = struct.unpack_from("h", flags, _IFNAMSIZ)[0]
            if not ifr_flags & _IFF_UP:
                state = "DOWN"
        except OSError:
            pass
        try:
            req = bytearray(struct.pack("16s", name.encode()) +
                            b"\x00" * (_SIZEOF_IFREQ - _IFNAMSIZ))
            fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, req)  # mutates req in place
            addresses.append(socket.inet_ntoa(bytes(req[_IFNAMSIZ + 4:_IFNAMSIZ + 8])))
        except OSError:
            # No IPv4 on this interface; not an error worth reporting.
            pass
        finally:
            sock.close()
        rows.append({"name": name, "state": state, "addresses": addresses})
    return rows


def interfaces() -> list[dict]:
    """Enumerate network interfaces using the best method this host supports."""
    if has_iproute2():
        res = runner.run(["ip", "-br", "addr"], timeout=10)
        if res.ok and (res.stdout or "").strip():
            rows = _rows_from_ip_brief(res.stdout)
            if rows:
                return rows
        res = runner.run(["ip", "addr", "show"], timeout=10)
        if res.ok and (res.stdout or "").strip():
            rows = _rows_from_ip_addr(res.stdout)
            if rows:
                return rows

    if shutil.which("ifconfig"):
        res = runner.run(["ifconfig", "-a"], timeout=10)
        if res.ok and (res.stdout or "").strip():
            rows = _rows_from_ifconfig(res.stdout)
            if rows:
                return rows

    rows = _rows_from_psutil()
    if rows:
        return rows

    return _rows_from_ioctl()


def interface_source() -> str:
    """Which detection path `interfaces()` would use — surfaced in diagnostics."""
    if has_iproute2():
        return "ip"
    if shutil.which("ifconfig"):
        return "ifconfig"
    try:
        import psutil  # noqa: F401
        return "psutil"
    except Exception:
        pass
    return "ioctl" if os.name == "posix" else "none"


def can_interfaces() -> dict:
    """Detect SocketCAN interfaces, including virtual vcan devices.

    On Android there is normally no SocketCAN at all, so an empty list plus a
    truthful reason is the correct answer rather than pretending.
    """
    found: list[dict] = []
    if has_iproute2():
        res = runner.run(["ip", "-details", "link", "show"], timeout=10)
        current = None
        for line in (res.stdout or "").splitlines():
            if line and not line.startswith(" "):
                current = line.split(":")[1].strip().split("@")[0] if ":" in line else None
            if "can" in line and current:
                found.append({"name": current, "detail": line.strip()})
    if not found:
        # python-can can still report interfaces without iproute2 present.
        try:
            import can
            for cfg in can.detect_available_configs():
                # Only real SocketCAN devices count as interfaces. python-can also
                # reports the 'virtual' backend, whose channel names are synthetic
                # placeholders (e.g. channel-5202), not links on this host.
                if cfg.get("interface") == "socketcan":
                    found.append({"name": str(cfg.get("channel")), "detail": str(cfg)})
        except Exception:
            pass
    return {"interfaces": found, "can_utils": has_can_utils(),
            "reason": None if found else ("no SocketCAN interface on this platform"
                                          if (is_android() or not has_iproute2())
                                          else "no CAN interface present")}


# ---------------------------------------------------------------------------
# Addressing helpers — what makes the phone reachable
# ---------------------------------------------------------------------------
def _usable_ipv4(addresses: list[str]) -> str | None:
    """Pick a routable IPv4: skip loopback and link-local."""
    for raw in addresses:
        ip = raw.split("/", 1)[0]
        if ip.startswith("127.") or ip.startswith("169.254."):
            continue
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
            return ip
    return None


def primary_lan_ip() -> str | None:
    """Best guess at the address other devices on the LAN can reach.

    Prefers a real interface address; falls back to the UDP-connect trick, which
    needs no privileges and no external binary (it works on Termux).
    """
    override = os.environ.get("WD_PUBLIC_HOST")
    if override:
        return override
    for row in interfaces():
        candidate = _usable_ipv4(row.get("addresses") or [])
        if candidate:
            return candidate
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))  # no packet is sent for UDP connect
            ip = probe.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        finally:
            probe.close()
    except OSError:
        pass
    return None


DEFAULT_PORT = 8000


def _port_from_authority(authority: str | None) -> int | None:
    """The explicit port in an HTTP `authority`, or None when there is none.

    Handles `host:8080`, `[::1]:8000` and bare `host`. A bare hostname carries no
    port, so the caller must fall through to another source -- this function
    never invents one.
    """
    if not authority:
        return None
    authority = authority.rsplit("@", 1)[-1].strip()
    if authority.startswith("["):  # IPv6 literal
        _, _, tail = authority.partition("]")
        return int(tail[1:]) if tail.startswith(":") and tail[1:].isdigit() else None
    if authority.count(":") == 1:
        _, _, port = authority.partition(":")
        return int(port) if port.isdigit() else None
    return None


def serving_port(request_port: int | None = None,
                 headers: Mapping[str, str] | None = None) -> int:
    """The port this console is *actually* served on, in trust order.

    1. the `Host` header's explicit port -- what the client really dialled. On a
       direct connection this equals the socket port; behind a reverse proxy it
       is the client-facing port, which the socket port would get wrong.
    2. `request_port` -- the socket the request in flight arrived on.
    3. `WD_PORT` -- what `run.sh` / `termux.sh` export before exec'ing uvicorn.
    4. `DEFAULT_PORT`.

    This exists because the first version read only `WD_PORT`: a console started
    with `uvicorn --port 9187` and no exported `WD_PORT` advertised `:8000`, so a
    client -- and the APK's DETECT -- dialled a port nothing listens on. The
    advertised value has to be the one that answers.

    Only the *port* is taken from `Host`, never the hostname; the advertised
    host stays loopback/LAN. So a spoofed `Host` can at most misstate the port of
    this same console in an advisory, unauthenticated payload.
    """
    from_host = _port_from_authority((headers or {}).get("host"))
    if from_host:
        return int(from_host)
    if request_port:
        return int(request_port)
    env = os.environ.get("WD_PORT", "").strip()
    if env.isdigit():
        return int(env)
    return DEFAULT_PORT


def lan_urls(port: int | None = None, scheme: str = "http",
             headers: Mapping[str, str] | None = None) -> list[str]:
    """Every URL a client could use to reach this console.

    Loopback comes first because an on-device client (the APK next to a Termux
    console) must use 127.0.0.1, not the phone's LAN address.
    """
    p = serving_port(port, headers)
    urls = [f"{scheme}://127.0.0.1:{p}"]
    lan = primary_lan_ip()
    if lan:
        url = f"{scheme}://{lan}:{p}"
        if url not in urls:
            urls.append(url)
    return urls


def network_info(port: int | None = None,
                 headers: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Payload for GET /api/network — lets a client discover the console URL.

    `port` should be the port the request arrived on; see `serving_port`.
    """
    from backend import config
    p = serving_port(port, headers)
    urls = lan_urls(p)
    return {
        "platform": platform_label(),
        "is_termux": is_termux(),
        "is_android": is_android(),
        "is_wsl": is_wsl(),
        "port": p,
        "bind_host": os.environ.get("WD_HOST", "0.0.0.0"),
        "primary_lan_ip": primary_lan_ip(),
        "urls": urls,
        "on_device_url": urls[0],
        "lan_url": urls[1] if len(urls) > 1 else None,
        "interface_source": interface_source(),
        "has_iproute2": has_iproute2(),
        "can_utils": has_can_utils(),
        "instance": config.INSTANCE_NAME,
        "version": config.APP_VERSION,
    }


def capability_notes() -> list[str]:
    """Platform-specific caveats shown in the Capabilities view."""
    notes: list[str] = []
    if is_termux() or is_android():
        if not has_iproute2():
            notes.append("iproute2 (`ip`) is absent; interfaces are read via "
                         + interface_source() + ".")
        if not has_can_utils():
            notes.append("can-utils is absent; SocketCAN checks will report unavailable "
                         "unless an interface plus python-can are present.")
        notes.append("Live packet capture needs root (tsu) on Android; "
                     "lab mode needs no privileges.")
    if is_wsl():
        notes.append("WSL: raw capture works, but ARP/segmentation results describe the WSL "
                     "virtual switch, not the Windows host.")
    return notes
