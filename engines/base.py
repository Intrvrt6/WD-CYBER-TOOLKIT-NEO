"""Engine framework shared by every module.

Contract:
  * An engine declares `module`, `checks` and a `run(ctx)` that executes real
    work and appends Result objects.
  * Every Result records HOW it was obtained (`source`: live | lab | local |
    unavailable) so no finding can ever masquerade as something it is not.
  * A check that could not run produces an `unavailable` Result with the reason
    instead of a fabricated pass/fail.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import time
from typing import Any, Callable, Iterable

from backend import config, runner


@dataclasses.dataclass
class Result:
    check_id: str
    title: str
    status: str                 # pass | fail | info | unavailable | error
    severity: str = "info"      # critical|high|medium|low|info
    description: str = ""
    asset: str = ""
    source: str = "live"        # live | lab | local | unavailable
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe: list[str] = dataclasses.field(default_factory=list)
    remediation: str = ""
    evidence: list[dict] = dataclasses.field(default_factory=list)
    data: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Context:
    assessment_id: str
    module: str
    mode: str                    # live | lab
    intensity: str               # light | normal | deep
    targets: list[str]
    params: dict[str, Any]
    evidence_dir: str
    log: Callable[[str, str], None] = lambda level, msg: None
    progress: Callable[[int], None] = lambda pct: None
    findings: list[Result] = dataclasses.field(default_factory=list)

    def add(self, result: Result) -> Result:
        self.findings.append(result)
        self.log("info", f"[{result.check_id}] {result.status}: {result.title}")
        return result

    def path(self, name: str) -> str:
        os.makedirs(self.evidence_dir, exist_ok=True)
        return os.path.join(self.evidence_dir, name)

    def save_text(self, name: str, text: str) -> dict:
        p = self.path(name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return artifact(p, name, "text/plain")


# --------------------------------------------------------------- utilities --
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(path: str, name: str, kind: str = "file") -> dict:
    size = os.path.getsize(path) if os.path.exists(path) else 0
    return {"name": name, "path": path, "kind": kind, "size": size,
            "sha256": sha256_file(path) if os.path.exists(path) else ""}


def tool_version(name: str, argv: list[str]) -> str:
    res = runner.run(argv, timeout=10)
    for line in (res.stdout or res.stderr or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return "unknown"


def have(binary: str) -> bool:
    import shutil
    return shutil.which(binary) is not None


def unavailable(check_id: str, title: str, reason: str, asset: str = "") -> Result:
    return Result(check_id=check_id, title=title, status="unavailable", severity="info",
                  description=reason, asset=asset, source="unavailable",
                  evidence=[{"type": "other", "summary": reason}])


def cidr_hosts(cidr: str, limit: int = 1024) -> list[str]:
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    out = []
    for ip in net.hosts():
        out.append(str(ip))
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- registry --
_REGISTRY: dict[str, type] = {}


def register(cls):
    _REGISTRY[cls.module] = cls
    return cls


def get_engine(module: str):
    if module not in _REGISTRY:
        raise KeyError(f"unknown module '{module}'")
    return _REGISTRY[module]()


def modules() -> list[str]:
    return sorted(_REGISTRY)


def module_catalog() -> list[dict]:
    out = []
    for name in modules():
        eng = _REGISTRY[name]()
        out.append({"module": name, "title": eng.title, "description": eng.description,
                    "checks": [{"id": c[0], "title": c[1], "active": c[2]} for c in eng.checks]})
    return out
