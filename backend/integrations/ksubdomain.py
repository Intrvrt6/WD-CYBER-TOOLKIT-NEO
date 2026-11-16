"""ksubdomain adapter - real subdomain brute force via the CLI.

ksubdomain is stateless (no DNS-log dependency) and needs raw-socket privileges.
We keep the run bounded, verify input files exist, and return the reason when the
binary or privileges are missing instead of an empty 'clean' result.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from backend import config, runner


def binary() -> str | None:
    return os.environ.get("WD_KSUBDOMAIN_BIN") or shutil.which("ksubdomain")


def version() -> str | None:
    b = binary()
    if not b:
        return None
    res = runner.run([b, "-version"], timeout=15)
    for line in (res.stdout or res.stderr or "").splitlines():
        if line.strip():
            return line.strip()[:160]
    return "unknown"


def default_dict() -> Path | None:
    for candidate in (config.SAMPLES_DIR / "subdomains.txt",
                      Path.home() / "subdomain.txt"):
        if candidate.exists():
            return candidate
    return None


def enum(domain: str, dict_path: str | None = None, duration_s: int = 90,
         bandwidth: str = "2m", extra_args: list[str] | None = None) -> dict[str, Any]:
    """Brute-force subdomains for one apex domain."""
    b = binary()
    if not b:
        return {"available": False, "reason": "ksubdomain not installed (set WD_KSUBDOMAIN_BIN)",
                "domain": domain, "subdomains": []}
    d = Path(dict_path) if dict_path else default_dict()
    if d is None or not d.exists():
        return {"available": False,
                "reason": "no dictionary found (pass dict_path or add samples/subdomains.txt)",
                "domain": domain, "subdomains": []}

    out = Path(tempfile.mkdtemp(prefix="ksub_")) / "out.txt"
    argv = [b, "enum", "-d", domain, "-f", str(d), "-o", str(out),
            "-bw", bandwidth, "--silent"]
    if extra_args:
        argv += [a for a in extra_args if isinstance(a, str)]
    res = runner.run(argv, timeout=max(30, min(duration_s, 300)))

    subdomains: list[str] = []
    if out.exists():
        subdomains = [ln.strip() for ln in out.read_text(errors="replace").splitlines() if ln.strip()]
    if not subdomains:
        for line in (res.stdout or "").splitlines():
            line = line.strip()
            if domain in line and " " not in line:
                subdomains.append(line)
    seen, unique = set(), []
    for s in subdomains:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    perm_note = ""
    low = (res.stderr or "").lower()
    if "permission" in low or "operation not permitted" in low or "pcap" in low:
        perm_note = "raw-socket capability missing: run as root or grant CAP_NET_RAW"
    return {
        "available": True, "binary": b, "version": version(), "domain": domain,
        "dictionary": str(d), "subdomains": unique, "count": len(unique),
        "returncode": res.returncode, "timed_out": res.timed_out,
        "note": perm_note, "stderr_tail": (res.stderr or "")[-600:],
        "evidence": res.as_evidence(),
    }
