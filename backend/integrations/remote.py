"""Thin REST clients for the ARTEX and ScopeSentry services.

Both are optional: if the service is not configured or unreachable, every call
returns available=False with the concrete reason. Nothing is simulated.
"""
from __future__ import annotations

import os
from typing import Any

import httpx


def _base(env: str) -> str:
    return (os.environ.get(env) or "").rstrip("/")


def _headers(token_env: str) -> dict[str, str]:
    t = os.environ.get(token_env)
    return {"authorization": f"Bearer {t}"} if t else {}


def _get(url: str, headers: dict[str, str], params: dict | None = None,
         timeout: int = 15) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=timeout, verify=False) as c:
            r = c.get(url, headers=headers, params=params)
        body: Any
        try:
            body = r.json()
        except ValueError:
            body = (r.text or "")[:2000]
        return {"available": r.status_code < 500, "status_code": r.status_code, "body": body,
                "url": url}
    except Exception as exc:
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}", "url": url}


# ------------------------------------------------------------------ ARTEX ---
def artex_status() -> dict[str, Any]:
    base = _base("WD_ARTAX_URL")
    if not base:
        return {"available": False, "reason": "not configured (set WD_ARTAX_URL)"}
    return _get(base + "/api/auth/status", _headers("WD_ARTAX_TOKEN"))


def artex_stats() -> dict[str, Any]:
    base = _base("WD_ARTAX_URL")
    if not base:
        return {"available": False, "reason": "not configured (set WD_ARTAX_URL)"}
    return _get(base + "/api/stats", _headers("WD_ARTAX_TOKEN"))


def artex_tasks(limit: int = 20) -> dict[str, Any]:
    base = _base("WD_ARTAX_URL")
    if not base:
        return {"available": False, "reason": "not configured (set WD_ARTAX_URL)"}
    return _get(base + "/api/tasks", _headers("WD_ARTAX_TOKEN"), params={"limit": limit})


# ------------------------------------------------------------ ScopeSentry ---
def scopesentry_health() -> dict[str, Any]:
    base = _base("WD_SCOPESENTRY_URL")
    if not base:
        return {"available": False, "reason": "not configured (set WD_SCOPESENTRY_URL)"}
    for path in ("/api/health", "/api/asset", "/"):
        out = _get(base + path, _headers("WD_SCOPESENTRY_TOKEN"))
        if out.get("available"):
            return out
    return out


def scopesentry_assets(page: int = 1, size: int = 20) -> dict[str, Any]:
    base = _base("WD_SCOPESENTRY_URL")
    if not base:
        return {"available": False, "reason": "not configured (set WD_SCOPESENTRY_URL)"}
    return _get(base + "/api/asset", _headers("WD_SCOPESENTRY_TOKEN"),
                params={"page": page, "size": size})
