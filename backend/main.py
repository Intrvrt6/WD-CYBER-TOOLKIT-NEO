"""WD CYBER TOOLKIT NEO - FastAPI application entrypoint."""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend import (authentication, authorization, config, database,
                     emergency_stop, runner)
from backend.api import auth as auth_api
from backend.api import artax_api, core_api, integrations_api, reports_api

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("wd.neo")


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.load_dotenv()
    config.ensure_dirs()
    database.init_db()
    db = database.SessionLocal()
    try:
        creds = authentication.bootstrap(db)
        if creds:
            log.warning("=" * 72)
            log.warning("WD CYBER TOOLKIT NEO - bootstrap operator created")
            log.warning("  username : %s", creds["username"])
            log.warning("  password : %s", creds["password"])
            log.warning("  stage-2 PIN   : %s", creds["pin"])
            log.warning("  WD shortcut   : %s", creds["shortcut"])
            log.warning("  also written to %s", config.DATA_DIR / "bootstrap_credentials.txt")
            log.warning("=" * 72)
        stop = emergency_stop.state(db)
        if stop.get("active"):
            runner.executor.request_stop()
            log.warning("Emergency stop was ACTIVE at startup; execution is blocked until cleared.")
        import engines
        st = engines.status()
        log.info("Engines registered: %s", ", ".join(st["registered"]) or "none")
        from backend.artax import get_client as _artax
        _ax = _artax().status()
        log.info("Artax AI mode: %s (model=%s, endpoint=%s)", _ax["mode"], _ax["model"],
                 _ax["endpoint"] or "none")
        if st["failed"]:
            for m, err in st["failed"].items():
                log.warning("Engine module %s unavailable: %s", m, err)
    finally:
        db.close()
    yield


app = FastAPI(title=config.INSTANCE_NAME, version=config.APP_VERSION, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")

# Same-origin is the secure default. Explicitly trust only origins supplied by
# WD_CORS_ORIGINS (comma-separated); config rejects wildcard and unsafe origins.
app.add_middleware(
    CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["Content-Disposition"], max_age=600,
)

app.include_router(auth_api.router)
app.include_router(core_api.router)
app.include_router(reports_api.router)
app.include_router(artax_api.router)
app.include_router(integrations_api.router)


@app.exception_handler(authentication.AuthError)
async def _auth_err(_req: Request, exc: authentication.AuthError):
    return JSONResponse(status_code=exc.status, content={"detail": {"code": exc.code, "message": exc.message}})


@app.exception_handler(authorization.ScopeError)
async def _scope_err(_req: Request, exc: authorization.ScopeError):
    """Scope/authorization/emergency-stop violations are client errors, not 500s."""
    return JSONResponse(status_code=exc.status, content={"detail": {"code": exc.code, "message": exc.message}})


@app.get("/api/version")
def version():
    return {"instance": config.INSTANCE_NAME, "version": config.APP_VERSION,
            "python": sys.version.split()[0]}


if config.FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(config.FRONTEND_DIR / "assets")), name="assets")

    _FRONTEND_ROOT = config.FRONTEND_DIR.resolve()
    _SERVABLE = {".html", ".js", ".css", ".svg", ".ico", ".png", ".webmanifest",
                 ".json", ".map", ".woff", ".woff2", ".ttf"}

    def _safe_static(path: str) -> Path | None:
        """Resolve `path` under frontend/ or return None.

        The SPA catch-all used to compute ``FRONTEND_DIR / path`` and serve the
        result whenever it was a file. ``path`` is attacker-controlled and FastAPI
        passes the percent-decoded remainder, so ``..%2f..%2fdatabase%2f...``
        escaped the frontend directory: an unauthenticated GET could read any file
        the process can read, including database/bootstrap_credentials.txt with the
        operator password, stage-2 PIN and WD shortcut in cleartext. Containment is
        checked on the *resolved* path so symlinks cannot escape either.
        """
        if not path or path.startswith(("/", chr(92))) or chr(0) in path:
            return None
        try:
            candidate = (config.FRONTEND_DIR / path).resolve()
        except (OSError, ValueError):
            return None
        try:
            candidate.relative_to(_FRONTEND_ROOT)
        except ValueError:
            return None
        return candidate if candidate.is_file() else None

    @app.get("/")
    def index():
        return FileResponse(str(config.FRONTEND_DIR / "index.html"))

    @app.get("/{path:path}")
    def spa(path: str):
        hit = _safe_static(path)
        if path.startswith("api/"):
            if hit is None:
                return JSONResponse(status_code=404, content={"detail": "not found"})
            return FileResponse(str(hit))
        if hit is not None and hit.suffix in _SERVABLE:
            return FileResponse(str(hit))
        # Any other route (or an attempt to leave frontend/) renders the SPA.
        return FileResponse(str(config.FRONTEND_DIR / "index.html"))


def run() -> None:
    import uvicorn
    host = os.environ.get("WD_HOST", "127.0.0.1")
    port = int(os.environ.get("WD_PORT", "8000"))
    uvicorn.run("backend.main:app", host=host, port=port, log_level="info", workers=1)


if __name__ == "__main__":
    run()
