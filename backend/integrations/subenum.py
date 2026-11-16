"""ksubdomain adapter - stateless subdomain enumeration.

ksubdomain sends DNS queries over raw sockets (libpcap), so it needs CAP_NET_RAW.
When that is missing we report it instead of returning an empty result, because
"no subdomains" and "could not send packets" are very different answers.
"""
from __future__ import annotations

import os
import re
import shutil
from typing import Any

from backend import runner

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_FOUND = re.compile(r"^([A-Za-z0-9_.*-]+)\s*=>\s*([0-9a-fA-F:.]+|CNAME)\s*$")


def binary() -> str | None:
    return os.environ.get("WD_KSUBDOMAIN_BIN") or shutil.which("ksubdomain")


def version() -> str | None:
    b = binary()
    if not b:
        return None
    res = runner.run([b, "version"], timeout=15)
    return (res.stdout or "").strip().splitlines()[-1][:80] if res.stdout.strip() else "unknown"


def enumerate_domain(domain: str, timeout_s: int = 90,
                     extra_args: list[str] | None = None) -> dict[str, Any]:
    """Enumerate subdomains for one authorized apex domain."""
    b = binary()
    if not b:
        return {"available": False, "reason": "ksubdomain not installed (set WD_KSUBDOMAIN_BIN)",
                "domain": domain, "subdomains": []}
    argv = [b, "enum", "-d", domain, "-silent"]
    if extra_args:
        argv += [a for a in extra_args if isinstance(a, str)]
    res = runner.run(argv, timeout=max(20, min(timeout_s, 300)))
    raw = _ANSI.sub("", (res.stdout or "") + "\n" + (res.stderr or ""))

    subdomains: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip().strip("\r")
        m = _FOUND.match(line)
        if m:
            subdomains.append({"subdomain": m.group(1), "resolves_to": m.group(2)})
    seen, unique = set(), []
    for s in subdomains:
        if s["subdomain"] not in seen:
            seen.add(s["subdomain"])
            unique.append(s)

    permission_denied = "permission denied" in raw.lower() or "operation not permitted" in raw.lower()
    return {
        "available": not permission_denied,
        "reason": ("raw-socket permission denied; grant CAP_NET_RAW or run as root"
                   if permission_denied else None),
        "binary": b, "version": version(), "domain": domain,
        "subdomains": unique, "count": len(unique),
        "returncode": res.returncode, "timed_out": res.timed_out,
        "device_line": next((l for l in raw.splitlines() if "Use Device" in l), ""),
    }
