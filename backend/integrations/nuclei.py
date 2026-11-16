"""nuclei adapter for the vendored oscuridad SQLi template set.

Two upstream details matter here and both were verified against nuclei v3.11.1:

1. All three templates declare the SAME id (`oscuridad-sql`), so passing them as
   three `-t` flags makes nuclei fail with "no templates provided for scan".
   Always pass the DIRECTORY (or the workflow).
2. These templates use `fuzzing:` (DAST), which nuclei disables by default.
   Without `-dast` the scan loads zero templates and exits with an FTL error.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from backend import config, runner


def template_dir() -> Path:
    env = os.environ.get("WD_NUCLEI_TEMPLATE_DIR")
    return Path(env) if env else config.TEMPLATES_DIR / "nuclei" / "oscuridad" / "sql"


def workflow_path() -> Path:
    return config.TEMPLATES_DIR / "nuclei" / "oscuridad-sql-workflow.yaml"


def binary() -> str | None:
    return os.environ.get("WD_NUCLEI_BIN") or shutil.which("nuclei")


def version() -> str | None:
    b = binary()
    if not b:
        return None
    res = runner.run([b, "-version"], timeout=15)
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if line.lower().startswith("nuclei engine version") or "nuclei" in line.lower():
            return line[:160]
    return "unknown"


def list_templates() -> dict[str, Any]:
    td = template_dir()
    files = sorted(p.name for p in td.glob("*.yaml")) if td.exists() else []
    return {"dir": str(td), "exists": td.exists(), "templates": files,
            "count": len(files), "workflow": str(workflow_path()),
            "workflow_exists": workflow_path().exists()}


def run_sqli(url: str, use_workflow: bool = False, timeout_s: int = 90,
             extra_args: list[str] | None = None) -> dict[str, Any]:
    """Run the vendored SQLi templates against one URL."""
    b = binary()
    if not b:
        return {"available": False, "reason": "nuclei not installed (set WD_NUCLEI_BIN)",
                "findings": [], "url": url}
    td = template_dir()
    if not td.exists():
        return {"available": False, "reason": f"template dir missing: {td}",
                "findings": [], "url": url}

    # -dast is REQUIRED: the vendored templates are fuzzing (DAST) templates.
    argv = [b, "-u", url, "-dast", "-silent", "-nc", "-no-color", "-stats=false",
            "-jsonl", "-timeout", "10", "-retries", "0", "-disable-update-check"]
    if use_workflow and workflow_path().exists():
        argv += ["-w", str(workflow_path())]
    else:
        argv += ["-t", str(td)]
    if extra_args:
        argv += [a for a in extra_args if isinstance(a, str)]

    res = runner.run(argv, timeout=max(30, min(timeout_s, 300)))
    findings: list[dict[str, Any]] = []
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = ev.get("info") or {}
        findings.append({
            "template_id": ev.get("template-id"),
            "name": info.get("name"),
            "severity": (info.get("severity") or "info").lower(),
            "matched_at": ev.get("matched-at") or ev.get("host"),
            "matcher": ev.get("matcher-name"),
            "type": ev.get("type"),
        })
    notes = []
    tail = (res.stderr or "").strip()
    low = tail.lower()
    if "no templates provided" in low:
        notes.append("nuclei reported no templates: pass the directory, not repeated -t files")
    if "dast template" in low and "excluded" in low:
        notes.append("DAST templates were excluded: -dast is required for these fuzzing templates")
    if "excluded" in low and "deprecated" in low:
        notes.append("a template uses deprecated syntax; it still ran")
    return {
        "available": True, "binary": b, "version": version(), "url": url,
        "templates": list_templates(), "findings": findings, "count": len(findings),
        "used_workflow": bool(use_workflow and workflow_path().exists()),
        "returncode": res.returncode, "timed_out": res.timed_out,
        "notes": notes, "stderr_tail": tail[-600:], "evidence": res.as_evidence(),
    }
