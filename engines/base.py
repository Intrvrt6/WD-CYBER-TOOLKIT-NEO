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
import hashlib
import os
from typing import Any, Callable

from backend import runner


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
    # Every file this assessment wrote, with its size and SHA-256. The
    # orchestrator persists these as Artifact rows, so evidence integrity is
    # recorded even when an engine ignores save_text()'s return value.
    artifacts: list[dict] = dataclasses.field(default_factory=list)

    def add(self, result: Result) -> Result:
        self.findings.append(result)
        self.log("info", f"[{result.check_id}] {result.status}: {result.title}")
        return result

    def path(self, name: str) -> str:
        os.makedirs(self.evidence_dir, exist_ok=True)
        return os.path.join(self.evidence_dir, name)

    def save_text(self, name: str, text: str, kind: str = "text/plain") -> dict:
        """Write a text artifact and REGISTER it on this context.

        Registration is the point: engines historically called save_text() for
        its side effect and dropped the return value, so the file landed on disk
        while no Artifact row (and no SHA-256) was ever recorded. Registering
        here makes the evidence trail independent of caller discipline.
        """
        p = self.path(name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return self.register(p, name, kind)

    def save_bytes(self, name: str, blob: bytes, kind: str = "file") -> dict:
        """Write a binary artifact (pcap, xml, apk) and register it."""
        p = self.path(name)
        with open(p, "wb") as fh:
            fh.write(blob)
        return self.register(p, name, kind)

    def register(self, path: str, name: str | None = None, kind: str = "file") -> dict:
        """Record an existing file as evidence for this assessment."""
        meta = artifact(path, name or os.path.basename(path), kind)
        key = meta["path"]
        if not any(a.get("path") == key for a in self.artifacts):
            self.artifacts.append(meta)
        return meta


# --------------------------------------------------------------- utilities --
def sha256_file(path: str) -> str:
    """SHA-256 of a file's bytes.

    A directory is also accepted: its digest is computed over a sorted manifest
    of (relative path, file digest) pairs, so a rule directory still has a
    meaningful, reproducible integrity value instead of raising.
    """
    if os.path.isdir(path):
        h = hashlib.sha256()
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, path).replace(os.sep, "/")
                h.update(rel.encode("utf-8"))
                h.update(b"\x00")
                h.update(sha256_file(full).encode("ascii"))
                h.update(b"\n")
        return h.hexdigest()
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(path: str, name: str, kind: str = "file") -> dict:
    """Describe one evidence artifact, with a computed size and SHA-256.

    Directories are supported: size is the sum of the files inside, and the
    digest covers a sorted manifest (see sha256_file).
    """
    if not os.path.exists(path):
        return {"name": name, "path": path, "kind": kind, "size": 0, "sha256": ""}
    if os.path.isdir(path):
        total = 0
        for root, _dirs, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        return {"name": name, "path": path, "kind": kind or "directory",
                "size": total, "sha256": sha256_file(path)}
    return {"name": name, "path": path, "kind": kind,
            "size": os.path.getsize(path), "sha256": sha256_file(path)}


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
