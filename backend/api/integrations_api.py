"""Upstream integration endpoints: catalog, live status, and proxied calls."""
from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from backend import audit
from backend.database import get_db
from backend.deps import Principal, current_principal
from backend.integrations import catalog, status
from backend.integrations import katana, ksubdomain, nuclei, remote

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


@router.get("")
def list_integrations(p: Principal = Depends(current_principal)):
    """Pinned upstream metadata: repo, license, revision, role, env vars."""
    return {"integrations": catalog()}


@router.get("/status")
def integration_status(p: Principal = Depends(current_principal)):
    """Live probe: which upstreams actually answer right now, and why not."""
    return {"status": status()}


@router.get("/artex/overview")
def artex_overview(p: Principal = Depends(current_principal)):
    return {"auth": remote.artex_status(), "stats": remote.artex_stats(),
            "tasks": remote.artex_tasks()}


@router.get("/scopesentry/overview")
def scopesentry_overview(page: int = Query(default=1, ge=1), size: int = Query(default=20, le=100),
                         p: Principal = Depends(current_principal)):
    return {"health": remote.scopesentry_health(), "assets": remote.scopesentry_assets(page, size)}


class CrawlIn(BaseModel):
    url: str = Field(min_length=4, max_length=2000)
    depth: int = Field(default=2, ge=1, le=5)
    duration_s: int = Field(default=45, ge=5, le=300)
    concurrency: int = Field(default=5, ge=1, le=10)
    js_crawl: bool = False
    headless: bool = False


@router.post("/katana/crawl")
def katana_crawl(body: CrawlIn, p: Principal = Depends(current_principal),
                 db: OrmSession = Depends(get_db)):
    """Run a real katana crawl. Keep -jsl off unless headless is requested (memory)."""
    out = katana.crawl(body.url, depth=body.depth, duration_s=body.duration_s,
                       concurrency=body.concurrency, js_crawl=body.js_crawl,
                       headless=body.headless)
    audit.record("integration.katana.crawl", actor=p.username, target=body.url,
                 detail={"count": out.get("count"), "available": out.get("available"),
                         "depth": body.depth, "js_crawl": body.js_crawl}, db=db)
    if not out.get("available"):
        raise HTTPException(status_code=503, detail=out.get("reason", "katana unavailable"))
    out.pop("evidence", None)  # keep the response small; raw output stays in the audit detail
    return out

@router.get("/nuclei/templates")
def nuclei_templates(p: Principal = Depends(current_principal)):
    """The vendored oscuridad SQLi set and where it lives."""
    return {"available": nuclei.binary() is not None,
            "binary": nuclei.binary(), "version": nuclei.version(),
            **nuclei.list_templates()}


class NucleiIn(BaseModel):
    url: str = Field(min_length=4, max_length=2000)
    use_workflow: bool = False
    timeout_s: int = Field(default=90, ge=30, le=300)


@router.post("/nuclei/sqli")
def nuclei_sqli(body: NucleiIn, p: Principal = Depends(current_principal),
                db: OrmSession = Depends(get_db)):
    """Run the vendored SQLi templates. -dast is mandatory (fuzzing templates)."""
    out = nuclei.run_sqli(body.url, use_workflow=body.use_workflow, timeout_s=body.timeout_s)
    audit.record("integration.nuclei.sqli", actor=p.username, target=body.url,
                 detail={"count": out.get("count"), "available": out.get("available"),
                         "workflow": out.get("used_workflow")}, db=db)
    if not out.get("available"):
        raise HTTPException(status_code=503, detail=out.get("reason", "nuclei unavailable"))
    out.pop("evidence", None)
    return out


class KsubIn(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    dict_path: str | None = None
    duration_s: int = Field(default=60, ge=30, le=300)
    bandwidth: str = Field(default="2m", max_length=8)


@router.post("/ksubdomain/enum")
def ksubdomain_enum(body: KsubIn, p: Principal = Depends(current_principal),
                    db: OrmSession = Depends(get_db)):
    out = ksubdomain.enum(body.domain, dict_path=body.dict_path,
                          duration_s=body.duration_s, bandwidth=body.bandwidth)
    audit.record("integration.ksubdomain.enum", actor=p.username, target=body.domain,
                 detail={"count": out.get("count"), "available": out.get("available")}, db=db)
    if not out.get("available"):
        raise HTTPException(status_code=503, detail=out.get("reason", "ksubdomain unavailable"))
    out.pop("evidence", None)
    return out
