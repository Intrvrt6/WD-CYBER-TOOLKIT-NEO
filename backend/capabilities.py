"""Dependency and capability detection.

The UI and every engine ask this module what really exists on this host.
A missing tool is reported as missing; nothing is silently faked.
"""
from __future__ import annotations

import importlib
import re
import shutil
from functools import lru_cache

from backend import platform_utils, runner

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
    "candump": ["candump"],
    "cansend": ["cansend"],
    "cangen": ["cangen"],
    "ip": ["ip", "-V"],
    "iptables": ["iptables", "--version"],
    "nft": ["nft", "--version"],
    "ss": ["ss", "-V"],
    "jq": ["jq", "--version"],
    "testssl.sh": ["testssl.sh", "--version"],
    "dumpcap": ["dumpcap", "--version"],
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
                        # Prefer installed-distribution metadata: several packages
                        # (argon2-cffi, PyJWT) deprecate or omit module.__version__.
                        "version": str(_meta_version(pkg)
                                       or getattr(m, "__version__", None) or "unknown")}
        except Exception as exc:
            out[mod] = {"present": False, "package": pkg, "error": f"{type(exc).__name__}: {exc}"}
    return out


def _meta_version(pkg: str) -> str | None:
    try:
        from importlib.metadata import version
        return version(pkg)
    except Exception:
        return None


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_VERSION_TOKEN = re.compile(
    r"(?:v|version\s*:?\s*)?(\d+\.\d+(?:\.\d+)*(?:[-+~][0-9A-Za-z.~-]+)?)", re.IGNORECASE)
# Lines that are banners, usage text, warnings or errors rather than a version.
_NOT_A_VERSION = re.compile(
    r"(^\s*[-_/\\|<>()'`.^]+\s*$|"
    r"invalid option|unrecognized option|unknown option|no such file|not found|"
    r"^usage|usage: |copyright|licensed under|free software|options:|"
    r"unable to |cannot |could not |permission denied|protocol not supported)",
    re.IGNORECASE)


def _clean(text: str) -> str:
    return _ANSI.sub("", text or "").strip()


def extract_version(stdout: str, stderr: str) -> str:
    """Return a real version string from a tool's output, or "".

    Many CLI tools print an ASCII-art banner before the version (httpx, naabu,
    katana, dnsx, tlsx, subfinder, nuclei) and some print usage/error text on
    the same stream. Taking the first non-empty line therefore put banner art or
    ``candump: invalid option -- '-'`` into the report's "Tools and Versions"
    section. Prefer, in order: a line whose version token is a real dotted
    version, then a non-banner non-error line that contains a version token,
    then the first non-banner, non-error line.
    """
    lines = []
    for stream in (stdout, stderr):
        for raw in (stream or "").splitlines():
            line = _clean(raw)
            if line:
                lines.append(line)
    cleaned = [ln for ln in lines if not _NOT_A_VERSION.search(ln)]
    for line in cleaned:
        m = _VERSION_TOKEN.search(line)
        if m:
            # group(1) is the bare dotted version; the optional issuer prefix
            # ("v", "version", "Version:") is dropped so the report shows a
            # version number rather than a label.
            return m.group(1).strip()[:40]
    # No dotted version anywhere: the binary exists but did not report one.
    # Returning "" makes the report say "present" instead of quoting usage text.
    return ""


@lru_cache(maxsize=1)
def cli_tools() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for name, argv in CLI_TOOLS.items():
        path = shutil.which(argv[0])
        if path is None:
            out[name] = {"present": False, "path": None, "version": None}
            continue
        res = runner.run(argv, timeout=12)
        version = extract_version(res.stdout or "", res.stderr or "")
        entry = {"present": True, "path": path, "version": version or None,
                 "version_known": bool(version)}
        if not version:
            # Honest: the binary exists but would not report a version.
            entry["reason"] = "binary present but printed no parseable version"
        out[name] = entry
    return out


def capture_interfaces() -> list[str]:
    """Capture-capable interfaces, as reported by dumpcap -D."""
    if shutil.which("dumpcap") is None:
        return []
    res = runner.run(["dumpcap", "-D"], timeout=12)
    ifaces = []
    for line in (res.stdout or "").splitlines():
        m = re.match(r"\s*\d+\.\s+(\S.*?)\s*$", _clean(line))
        if m:
            # dumpcap decorates names: "lo (Loopback)" -> "lo"
            ifaces.append(re.sub(r"\s*\([^)]*\)\s*$", "", m.group(1)).strip())
    return ifaces


def interfaces() -> list[dict]:
    """Network interfaces, via the platform abstraction.

    Delegated to backend.platform_utils so Android/Termux (which ships no
    iproute2) still reports its real addresses through a syscall fallback.
    """
    return platform_utils.interfaces()


def can_interfaces() -> dict:
    """Detect SocketCAN interfaces, including virtual vcan devices."""
    return platform_utils.can_interfaces()


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
        "capture_interfaces": capture_interfaces(),
        "can": can_interfaces(),
        "usb": usb_available(),
        "raw_socket": raw_socket_ok(),
        "platform": platform_utils.platform_label(),
        "is_termux": platform_utils.is_termux(),
        "is_android": platform_utils.is_android(),
        "interface_source": platform_utils.interface_source(),
        "primary_lan_ip": platform_utils.primary_lan_ip(),
        "lan_urls": platform_utils.lan_urls(),
        "platform_notes": platform_utils.capability_notes(),
    }
