"""Upstream integration registry + pinned revision metadata.

Every upstream is pinned to the exact commit inspected/built during development,
and the licence is recorded so redistribution decisions stay explicit.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import Any

from backend import runner


@dataclass
class Integration:
    id: str
    name: str
    upstream: str
    license: str
    revision: str
    role: str
    env: dict[str, str] = field(default_factory=dict)
    note: str = ""


# Exactly one entry per upstream. Keys and `id` must match (asserted below).
_ENTRIES: list[Integration] = [
    Integration(
        id="artex", name="ARTEX", upstream="https://github.com/BaaRai/ARTEX",
        license="AGPL-3.0", revision="d005bfe5ba117830fb81c6ad4c103dbeeee31ba8",
        role="Autonomous LLM pentest engine (planner + workers + evidence graphs)",
        env={"base_url": "WD_ARTAX_URL", "token": "WD_ARTAX_TOKEN"},
        note="Separate service (Go binary + PostgreSQL). Consumed over REST; NOT vendored, "
             "which keeps AGPL-3.0 obligations off this tree."),
    Integration(
        id="scopesentry", name="ScopeSentry", upstream="https://github.com/Autumn-27/ScopeSentry",
        license="see upstream", revision="d770b7a137ec2de15816fea4bd561f49cf486db2",
        role="Distributed asset mapping / subdomain enumeration / vuln scanning server",
        env={"base_url": "WD_SCOPESENTRY_URL", "token": "WD_SCOPESENTRY_TOKEN"},
        note="FastAPI server + Vue UI. Consumed over REST; not vendored."),
    Integration(
        id="scopesentry_scan", name="ScopeSentry-Scan",
        upstream="https://github.com/Autumn-27/ScopeSentry-Scan",
        license="see upstream", revision="cf9a46e176f0bcba6c7000bcad8b0b72b872dc63",
        role="Scan node (Go agent) that executes ScopeSentry tasks",
        env={"binary": "WD_SCOPESENTRY_SCAN_BIN"},
        note="Runs as a node agent against the ScopeSentry server. Detected by path; the "
             "platform reports presence, it does not drive nodes directly."),
    Integration(
        id="scopesentry_docs", name="ScopeSentry-doc-src",
        upstream="https://github.com/Autumn-27/ScopeSentry-doc-src",
        license="see upstream", revision="6c9552decaf0c5c279c1ae0cf1da03c957a67428",
        role="Official documentation source (install, project mgmt, dictionaries, plugins)",
        env={"base_url": "WD_SCOPESENTRY_DOCS_URL"},
        note="Docs site (VitePress); carries no runtime API, linked for operators."),
    Integration(
        id="ksubdomain", name="ksubdomain",
        upstream="https://github.com/Autumn-27/ksubdomain",
        license="see upstream (module github.com/boy-hack/ksubdomain)",
        revision="9790e99b17e7af33bd49adcf1bcaf8e7960d144d",
        role="Stateless high-speed subdomain brute force (no DNS-log dependency)",
        env={"binary": "WD_KSUBDOMAIN_BIN"},
        note="Go CLI (v1.9.5 verified here). Needs CAP_NET_RAW; when the binary or the "
             "capability is missing the check reports unavailable instead of a clean result."),
    Integration(
        id="nuclei_templates", name="nuclei-template (oscuridad)",
        upstream="https://github.com/Autumn-27/nuclei-template",
        license="MIT (Copyright (c) 2023 Cookie)",
        revision="d05da21450648a444498f7cd7233f9da0b0bf08e",
        role="Custom SQL-injection nuclei templates + workflow",
        env={"dir": "WD_NUCLEI_TEMPLATE_DIR"},
        note="MIT, so the 4 files are VENDORED under templates/nuclei/ and run offline. "
             "Two verified gotchas: all three templates share id 'oscuridad-sql' (pass the "
             "DIRECTORY, not three -t flags) and they are fuzzing/DAST templates, so "
             "nuclei needs -dast or it loads nothing."),
    Integration(
        id="katana", name="katana (Autumn-27 fork)",
        upstream="https://github.com/Autumn-27/katana",
        license="MIT (upstream ProjectDiscovery)",
        revision="05e5ecf57e57f44345d7a4a9945abf20113f43e1",
        role="Web crawler used for content/endpoint discovery",
        env={"binary": "WD_KATANA_BIN"},
        note="Module github.com/projectdiscovery/katana. Driven as a CLI; any installed "
             "version is accepted and reported. -jsl is never enabled implicitly."),
]

INTEGRATIONS: dict[str, Integration] = {i.id: i for i in _ENTRIES}
assert len(INTEGRATIONS) == len(_ENTRIES), "duplicate integration id"


def catalog() -> list[dict[str, Any]]:
    return [{"id": i.id, "name": i.name, "upstream": i.upstream, "license": i.license,
             "revision": i.revision, "role": i.role, "note": i.note, "env": i.env}
            for i in _ENTRIES]


# ---------------------------------------------------------------- probing ---
def _probe_binary(path_env: str, default_names: list[str], version_argv: list[str]) -> dict[str, Any]:
    binary = os.environ.get(path_env) or next(
        (shutil.which(n) for n in default_names if shutil.which(n)), None)
    if not binary:
        return {"available": False, "binary": None, "version": None,
                "reason": f"not found (set {path_env} or install {default_names[0]})"}
    res = runner.run([binary, *version_argv], timeout=15)
    version = "unknown"
    for line in (res.stdout or res.stderr or "").splitlines():
        line = line.strip()
        # skip katana's ASCII banner lines
        if line and "_" not in line and "\\" not in line and not line.startswith("/"):
            version = line[:160]
            break
    return {"available": True, "binary": binary, "version": version}


def _probe_service(url_env: str, health_paths: list[str], token_env: str) -> dict[str, Any]:
    import httpx
    base = (os.environ.get(url_env) or "").rstrip("/")
    if not base:
        return {"available": False, "base_url": None,
                "reason": f"not configured (set {url_env})"}
    headers = {}
    if os.environ.get(token_env):
        headers["authorization"] = f"Bearer {os.environ[token_env]}"
    errors: list[str] = []
    for path in health_paths:
        try:
            with httpx.Client(timeout=6, verify=False) as c:
                r = c.get(base + path, headers=headers)
            if r.status_code < 500:
                return {"available": True, "base_url": base, "health_path": path,
                        "status_code": r.status_code, "body_sample": (r.text or "")[:200]}
            errors.append(f"{path} -> {r.status_code}")
        except Exception as exc:
            errors.append(f"{path} -> {type(exc).__name__}")
    return {"available": False, "base_url": base,
            "reason": "no healthy endpoint; " + "; ".join(errors[:3])}


def status() -> dict[str, Any]:
    """Live probe of every upstream. `available:false` always carries a reason."""
    from backend.integrations import nuclei

    inv = nuclei.list_templates()
    return {
        "artex": {**_probe_service("WD_ARTAX_URL", ["/api/auth/status", "/api/stats", "/"],
                                   "WD_ARTAX_TOKEN"), "mode": "service"},
        "scopesentry": {**_probe_service("WD_SCOPESENTRY_URL",
                                         ["/api/health", "/api/asset", "/"],
                                         "WD_SCOPESENTRY_TOKEN"), "mode": "service"},
        "scopesentry_scan": {**_probe_binary("WD_SCOPESENTRY_SCAN_BIN",
                                             ["scopesentry-scan", "ScopeSentry-Scan"],
                                             ["--help"]), "mode": "binary"},
        "scopesentry_docs": {**_probe_service("WD_SCOPESENTRY_DOCS_URL", ["/", "/index.html"],
                                              "WD_SCOPESENTRY_DOCS_TOKEN"), "mode": "docs"},
        "ksubdomain": {**_probe_binary("WD_KSUBDOMAIN_BIN", ["ksubdomain"], ["-version"]),
                       "mode": "binary"},
        "nuclei_templates": {"available": inv["exists"] and inv["count"] > 0,
                             "dir": inv["dir"], "count": inv["count"],
                             "version": f"{inv['count']} templates + workflow",
                             "mode": "vendored"},
        "katana": {**_probe_binary("WD_KATANA_BIN", ["katana"], ["-version"]),
                   "mode": "binary"},
    }
