"""Report generation and evidence download endpoints."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session as OrmSession

from backend import audit, config
from backend.database import Artifact, Assessment, get_db
from backend.deps import (Principal, current_principal, ensure_assessment_access)
from backend.reports import generator

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/assessments/{assessment_id}/report")
def get_report(assessment_id: str, fmt: str = Query(default="pdf", pattern="^(pdf|html|md)$"),
               lang: str = Query(default="en", pattern="^(en|id)$"),
               download: bool = False,
               p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    ensure_assessment_access(a, p)
    try:
        content, mime, ext = generator.render(db, assessment_id, fmt, lang)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"report generation failed: {exc}")
    audit.record("report.generated", actor=p.username, target=assessment_id,
                 detail={"format": fmt, "lang": lang}, db=db)
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="wd_{assessment_id}_{lang}.{ext}"'
    return Response(content=content, media_type=mime, headers=headers)


@router.post("/assessments/{assessment_id}/report/save")
def save_report(assessment_id: str, fmt: str = Query(default="pdf", pattern="^(pdf|html|md)$"),
                lang: str = Query(default="en", pattern="^(en|id)$"),
                p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    ensure_assessment_access(a, p)
    path = generator.save(db, assessment_id, fmt, lang)
    audit.record("report.saved", actor=p.username, target=assessment_id,
                 detail={"path": path, "format": fmt, "lang": lang}, db=db)
    return {"path": path, "format": fmt, "lang": lang, "exists": os.path.exists(path),
            "size": os.path.getsize(path) if os.path.exists(path) else 0}


@router.get("/evidence/{assessment_id}/{artifact_id}")
def download_artifact(assessment_id: str, artifact_id: str,
                      p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    art = db.get(Artifact, artifact_id)
    if art is None or art.assessment_id != assessment_id:
        raise HTTPException(status_code=404, detail="artifact not found")
    assessment = db.get(Assessment, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    ensure_assessment_access(assessment, p)
    if not os.path.exists(art.path):
        raise HTTPException(status_code=410, detail="artifact file missing on disk")
    audit.record("evidence.downloaded", actor=p.username, target=art.name,
                 detail={"assessment": assessment_id, "sha256": art.sha256}, db=db)
    return FileResponse(art.path, filename=art.name, media_type="application/octet-stream")


@router.get("/evidence/samples")
def list_samples(p: Principal = Depends(current_principal)):
    out = []
    for root, _dirs, files in os.walk(str(config.SAMPLES_DIR)):
        for f in files:
            path = os.path.join(root, f)
            out.append({"name": f, "path": path, "size": os.path.getsize(path),
                        "rel": os.path.relpath(path, str(config.SAMPLES_DIR))})
    return {"samples": sorted(out, key=lambda x: x["rel"])}
