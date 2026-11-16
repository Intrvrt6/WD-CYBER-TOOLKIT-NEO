"""Boot-level smoke tests: the app must actually import and serve.

These exist because a green unit suite once hid a NameError in
`backend/orchestrator.py` that prevented `backend.main` from importing at all.
Unit tests imported the orchestrator's neighbours, not the app entrypoint.

Every test here imports/mounts the real application.
"""
from __future__ import annotations

import importlib
import pkgutil

import pytest


# ------------------------------------------------------------------ imports --
def test_backend_main_imports():
    """The FastAPI entrypoint must import without error (catches NameError)."""
    mod = importlib.import_module("backend.main")
    assert hasattr(mod, "app"), "backend.main exposes no app object"


def test_every_backend_module_imports():
    """Import every module under backend/ so a broken import cannot hide."""
    import backend

    failures = []
    for info in pkgutil.walk_packages(backend.__path__, prefix="backend."):
        try:
            importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001 - we want the message
            failures.append(f"{info.name}: {type(exc).__name__}: {exc}")
    assert not failures, "modules failed to import: " + "; ".join(failures)


def test_every_engine_module_imports():
    import engines  # noqa: F401
    from engines import base

    assert not engines.LOAD_ERRORS, f"engine import failures: {engines.LOAD_ERRORS}"
    for module in base.modules():
        eng = base.get_engine(module)
        assert callable(getattr(eng, "run", None)), module


def test_all_api_routers_mount():
    """Every router module must mount; a bad import would 404 the whole group."""
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as client:
        spec = client.get("/api/openapi.json").json()
    paths = spec["paths"]
    for expected in ("/api/health", "/api/auth/stage1", "/api/scope",
                     "/api/assessments", "/api/artax/status",
                     "/api/emergency-stop", "/api/audit/verify"):
        assert expected in paths, f"route missing from OpenAPI: {expected}"


def test_openapi_generates():
    """Pydantic schema generation must not raise for any route."""
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as client:
        r = client.get("/api/openapi.json")
    assert r.status_code == 200
    assert len(r.json()["paths"]) > 30


# ------------------------------------------------------------------ serving --
def test_index_html_is_served():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "CYBER TOOLKIT NEO" in r.text


def test_static_assets_are_served():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as client:
        for asset in ("app.css", "api.js", "ui.js", "app.js"):
            r = client.get(f"/assets/{asset}")
            assert r.status_code == 200, f"asset not served: {asset}"
            assert r.text.strip(), f"asset empty: {asset}"


def test_no_debug_endpoint_leaks_internals():
    """A stray debug route must not expose the environment or filesystem."""
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app) as client:
        spec = client.get("/api/openapi.json").json()["paths"]
    suspicious = [p for p in spec if any(k in p.lower() for k in ("debug", "env", "traceback"))]
    assert not suspicious, f"unexpected debug routes: {suspicious}"
