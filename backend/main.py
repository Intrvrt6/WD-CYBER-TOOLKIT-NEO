"""WD CYBER TOOLKIT NEO - FastAPI application entrypoint."""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

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

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=False,
    allow_methods=["*"], allow_headers=["*"], expose_headers=["Content-Disposition"],
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

    @app.get("/")
    def index():
        return FileResponse(str(config.FRONTEND_DIR / "index.html"))

    @app.get("/{path:path}")
    def spa(path: str):
        candidate = config.FRONTEND_DIR / path
        if candidate.is_file():
            return FileResponse(str(candidate))
        if path.startswith("api/"):
            return JSONResponse(status_code=404, content={"detail": "not found"})
        return FileResponse(str(config.FRONTEND_DIR / "index.html"))


def run() -> None:
    import uvicorn
    host = os.environ.get("WD_HOST", "0.0.0.0")
    port = int(os.environ.get("WD_PORT", "8000"))
    uvicorn.run("backend.main:app", host=host, port=port, log_level="info", workers=1)


if __name__ == "__main__":
    run()
