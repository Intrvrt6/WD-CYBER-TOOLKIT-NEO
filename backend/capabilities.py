"""Dependency and capability detection.

The UI and every engine ask this module what really exists on this host.
A missing tool is reported as missing; nothing is silently faked.
"""
from __future__ import annotations

import importlib
import shutil
from functools import lru_cache

from backend import runner

CLI_TOOLS = {
    "nmap": ["nmap", "--version"],
    "tshark": ["tshark", "-v"],
    "tcpdump": ["tcpdump", "--version"],
    "zeek": ["zeek", "--version"],
    "suricata": ["suricata", "--build-info"],
    "arp-scan": ["arp-scan", "--version"],
    "arping": ["arping", "--version"],
    "mitmproxy": ["mitmproxy", "--version"],
    "dig": ["dig", "-v"],
    "whois": ["whois", "--version"],
    "openssl": ["openssl", "version"],
    "nc": ["nc", "-h"],
    "curl": ["curl", "--version"],
    "subfinder": ["subfinder", "-version"],
    "httpx": ["httpx", "-version"],
    "naabu": ["naabu", "-version"],
    "nuclei": ["nuclei", "-version"],
    "katana": ["katana", "-version"],
    "dnsx": ["dnsx", "-version"],
    "tlsx": ["tlsx", "-version"],
    "ffuf": ["ffuf", "-V"],
    "sqlmap": ["sqlmap", "--version"],
    "nikto": ["nikto", "-Version"],
    "whatweb": ["whatweb", "--version"],
    "wafw00f": ["wafw00f", "--version"],
    "yara": ["yara", "--version"],
    "candump": ["candump", "--help"],
    "cansend": ["cansend", "--help"],
    "cangen": ["cangen", "--help"],
    "ip": ["ip", "-V"],
    "iptables": ["iptables", "--version"],
    "nft": ["nft", "--version"],
    "ss": ["ss", "-V"],
    "jq": ["jq", "--version"],
    "testssl.sh": ["testssl.sh", "--version"],
    "tshark_cap": ["dumpcap", "-D"],
    "socat": ["socat", "-V"],
    "git": ["git", "--version"],
}

PY_MODULES = {
    "fastapi": "fastapi", "uvicorn": "uvicorn", "sqlalchemy": "sqlalchemy",
    "argon2": "argon2-cffi", "jwt": "pyjwt", "httpx": "httpx",
    "reportlab": "reportlab", "jinja2": "jinja2", "yaml": "pyyaml",
    "scapy": "scapy", "can": "python-can", "pymodbus": "pymodbus",
    "asyncua": "asyncua", "yara": "yara-python", "psutil": "psutil",
    "pytest": "pytest",
}


@lru_cache(maxsize=1)
def python_modules() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for mod, pkg in PY_MODULES.items():
        try:
            m = importlib.import_module(mod)
            out[mod] = {"present": True, "package": pkg,
                        "version": str(getattr(m, "__version__", None) or _meta_version(pkg) or "unknown")}
        except Exception as exc:
            out[mod] = {"present": False, "package": pkg, "error": f"{type(exc).__name__}: {exc}"}
    return out


def _meta_version(pkg: str) -> str | None:
    try:
        from importlib.metadata import version
        return version(pkg)
    except Exception:
        return None


@lru_cache(maxsize=1)
def cli_tools() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name, argv in CLI_TOOLS.items():
        path = shutil.which(argv[0])
        if path is None:
            out[name] = {"present": False, "path": None, "version": None}
            continue
        res = runner.run(argv, timeout=12)
        first = ""
        for line in (res.stdout or "").splitlines():
            if line.strip():
                first = line.strip()[:160]
                break
        if not first:
            for line in (res.stderr or "").splitlines():
                if line.strip():
                    first = line.strip()[:160]
                    break
        out[name] = {"present": True, "path": path, "version": first}
    return out


def interfaces() -> list[dict]:
    res = runner.run(["ip", "-br", "addr"], timeout=10)
    rows = []
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            rows.append({"name": parts[0], "state": parts[1],
                         "addresses": [p for p in parts[2:] if p not in ("UP", "DOWN")]})
    return rows


def can_interfaces() -> dict:
    """Detect SocketCAN interfaces, including virtual vcan devices."""
    res = runner.run(["ip", "-details", "link", "show"], timeout=10)
    found = []
    current = None
    for line in (res.stdout or "").splitlines():
        if line and not line.startswith(" "):
            current = line.split(":")[1].strip().split("@")[0] if ":" in line else None
        if "can" in line and current:
            found.append({"name": current, "detail": line.strip()})
    return {"interfaces": found, "can_utils": shutil.which("candump") is not None}


def usb_available() -> dict:
    import os
    p = "/dev/bus/usb"
    if not os.path.isdir(p):
        return {"present": False, "path": p, "devices": []}
    try:
        devs = []
        for bus in sorted(os.listdir(p)):
            bdir = os.path.join(p, bus)
            if os.path.isdir(bdir):
                for dev in sorted(os.listdir(bdir)):
                    devs.append(f"{bus}/{dev}")
        return {"present": True, "path": p, "devices": devs}
    except PermissionError as exc:
        return {"present": False, "path": p, "error": str(exc)}


def raw_socket_ok() -> bool:
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except Exception:
        return False


def report() -> dict:
    import platform
    import os
    return {
        "host": {
            "platform": platform.platform(), "python": platform.python_version(),
            "system": platform.system(), "machine": platform.machine(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
        },
        "python_modules": python_modules(),
        "cli_tools": cli_tools(),
        "interfaces": interfaces(),
        "can": can_interfaces(),
        "usb": usb_available(),
        "raw_socket": raw_socket_ok(),
    }
