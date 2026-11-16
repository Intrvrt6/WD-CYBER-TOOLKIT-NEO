"""Scope, templates, assessments, jobs, findings, capabilities, emergency stop."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from backend import (audit, authorization, capabilities, emergency_stop, orchestrator,
                     templates_registry)
from backend.database import (Artifact, Assessment, Authorization, Finding, ScopeEntry,
                              get_db)
from backend.deps import (Principal, current_principal, require_role,
                         require_stage2, require_stage2_fresh_password)

router = APIRouter(prefix="/api", tags=["platform"])


# ------------------------------------------------------------------- health --
@router.get("/health")
def health(db: OrmSession = Depends(get_db)):
    import engines
    from backend import config
    return {
        "status": "ok", "instance": config.INSTANCE_NAME, "version": config.APP_VERSION,
        "database": str(db.bind.url).split("@")[-1] if db.bind else None,
        "engines": engines.status(),
        "emergency_stop": emergency_stop.state(db),
    }


@router.get("/capabilities")
def caps():
    return capabilities.report()


@router.get("/modules")
def modules():
    import engines
    from engines import base
    return {"modules": base.module_catalog(), **engines.status()}


# -------------------------------------------------------------------- scope --
class ScopeIn(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    target_type: str = "auto"
    description: str = ""


@router.get("/scope")
def list_scope(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    rows = db.execute(select(ScopeEntry).order_by(ScopeEntry.created_at.desc())).scalars().all()
    return {"scope": [{"id": s.id, "target": s.target, "target_type": s.target_type,
                       "description": s.description, "active": s.active,
                       "created_by": s.created_by,
                       "created_at": s.created_at.isoformat() if s.created_at else None} for s in rows]}


@router.post("/scope")
def add_scope(body: ScopeIn, p: Principal = Depends(require_role("admin", "operator")),
              db: OrmSession = Depends(get_db)):
    try:
        s = authorization.add_scope(db, body.target, body.target_type, body.description, p.username)
    except authorization.ScopeError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})
    return {"id": s.id, "target": s.target, "target_type": s.target_type}


@router.delete("/scope/{scope_id}")
def deactivate_scope(scope_id: str, p: Principal = Depends(require_role("admin", "operator")),
                     db: OrmSession = Depends(get_db)):
    s = db.get(ScopeEntry, scope_id)
    if s is None:
        raise HTTPException(status_code=404, detail="scope entry not found")
    s.active = False
    db.commit()
    audit.record("scope.deactivated", actor=p.username, target=s.target, db=db)
    return {"ok": True, "id": s.id}


class ValidateIn(BaseModel):
    targets: list[str]


@router.post("/scope/validate")
def validate_scope(body: ValidateIn, p: Principal = Depends(current_principal),
                   db: OrmSession = Depends(get_db)):
    return authorization.validate_targets(db, body.targets)


# ---------------------------------------------------------------- templates --
@router.get("/templates")
def list_templates(p: Principal = Depends(current_principal)):
    return {"templates": templates_registry.catalog()}


@router.get("/templates/{template_id}")
def get_template(template_id: str, p: Principal = Depends(current_principal)):
    try:
        return templates_registry.get(template_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ------------------------------------------------------------ authorization --
class AuthzIn(BaseModel):
    targets: list[str]
    ttl_minutes: int | None = None
    note: str = ""
    intended_test: str = ""


@router.post("/authorizations")
def create_authz(body: AuthzIn, p: Principal = Depends(require_stage2_fresh_password),
                 db: OrmSession = Depends(get_db)):
    emergency_stop.require_clear(db)
    try:
        a = authorization.create_authorization(db, p.user, p.session, body.targets,
                                               body.ttl_minutes, body.note or body.intended_test)
    except authorization.ScopeError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})
    return {"id": a.id, "targets": a.targets, "expires_at": a.expires_at.isoformat(),
            "confirmed": a.confirmed, "scope_snapshot": a.scope_snapshot,
            "intended_test": body.intended_test}


@router.get("/authorizations")
def list_authz(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    rows = db.execute(select(Authorization).order_by(Authorization.created_at.desc()).limit(100)).scalars().all()
    return {"authorizations": [{"id": a.id, "targets": a.targets, "confirmed": a.confirmed,
                                "revoked": a.revoked,
                                "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                                "note": a.note} for a in rows]}


# ------------------------------------------------------------- assessments --
class AssessmentIn(BaseModel):
    name: str = ""
    template: str
    targets: list[str]
    mode: str | None = None
    intensity: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


@router.post("/assessments")
def create_assessment(body: AssessmentIn, p: Principal = Depends(require_stage2_fresh_password),
                      db: OrmSession = Depends(get_db)):
    try:
        return orchestrator.create_assessment(db, p.user, body.name, body.template,
                                              body.targets, body.mode, body.intensity, body.params)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/assessments")
def list_assessments(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db),
                     limit: int = Query(default=50, le=200)):
    rows = db.execute(select(Assessment).order_by(Assessment.created_at.desc()).limit(limit)).scalars().all()
    return {"assessments": [orchestrator.assessment_dict(a) for a in rows]}


@router.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str, p: Principal = Depends(current_principal),
                   db: OrmSession = Depends(get_db)):
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    arts = db.execute(select(Artifact).where(Artifact.assessment_id == assessment_id)).scalars().all()
    return {**orchestrator.assessment_dict(a),
            "findings": orchestrator.findings_for(db, assessment_id),
            "artifacts": [{"id": x.id, "name": x.name, "path": x.path, "kind": x.kind,
                           "size": x.size, "sha256": x.sha256} for x in arts]}


class RunIn(BaseModel):
    authz_id: str
    confirm: bool = True
    confirm_text: str = ""


@router.post("/assessments/{assessment_id}/run")
def run_assessment(assessment_id: str, body: RunIn, p: Principal = Depends(require_stage2_fresh_password),
                   db: OrmSession = Depends(get_db)):
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    if not body.confirm:
        raise HTTPException(status_code=400, detail="explicit confirmation required")
    if a.operator != p.username and p.role != "admin":
        raise HTTPException(status_code=403, detail={
            "code": "ASSESSMENT_FOREIGN",
            "message": "Assessment belongs to operator '" + a.operator + "'."})
    existing = db.execute(select(orchestrator.Job).where(
        orchestrator.Job.assessment_id == assessment_id,
        orchestrator.Job.status.in_(("queued", "running")))).scalars().first()
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"assessment already running (job {existing.id})")
    try:
        return orchestrator.start_job(db, a, body.authz_id, p.username, user=p.user)
    except authorization.ScopeError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})


@router.get("/jobs/{job_id}")
def get_job(job_id: str, p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    state = orchestrator.job_state(db, job_id)
    if state is None:
        raise HTTPException(status_code=404, detail="job not found")
    return state


@router.get("/assessments/{assessment_id}/findings")
def get_findings(assessment_id: str, p: Principal = Depends(current_principal),
                 db: OrmSession = Depends(get_db)):
    return {"findings": orchestrator.findings_for(db, assessment_id)}


# ------------------------------------------------------------------- audit --
@router.get("/audit")
def get_audit(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db),
              limit: int = Query(default=200, le=2000), action: str | None = None):
    return {"events": audit.list_events(db, limit, action), "count": audit.count(db)}


@router.get("/audit/verify")
def verify_audit(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    return audit.verify_chain(db)


@router.get("/audit/export")
def export_audit(fmt: str = Query(default="json", pattern="^(json|csv)$"),
                 p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    from fastapi.responses import Response
    if fmt == "csv":
        return Response(audit.export_csv(db), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=wd_audit.csv"})
    return Response(audit.export_json(db), media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=wd_audit.json"})


# --------------------------------------------------------- emergency stop --
class StopIn(BaseModel):
    reason: str = "manual emergency stop"


@router.get("/emergency-stop")
def stop_state(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    return emergency_stop.state(db)


@router.post("/emergency-stop")
def stop_activate(body: StopIn, p: Principal = Depends(current_principal),
                  db: OrmSession = Depends(get_db)):
    """Any authenticated operator can HALT. Deliberately stage-1 sufficient."""
    result = emergency_stop.activate(db, actor=p.username, reason=body.reason)
    return result


@router.post("/emergency-stop/clear")
def stop_clear(p: Principal = Depends(require_stage2), db: OrmSession = Depends(get_db)):
    return emergency_stop.unlock(db, actor=p.username, reason="operator clear after re-authentication")


# ------------------------------------------------------------------ stats --
@router.get("/stats")
def stats(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    rows = db.execute(select(Assessment).order_by(Assessment.created_at.desc()).limit(200)).scalars().all()
    findings = db.execute(select(Finding).limit(5000)).scalars().all()
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    by_status: dict[str, int] = {}
    for a in rows:
        by_status[a.status] = by_status.get(a.status, 0) + 1
    scores = [a.risk_score for a in rows if a.risk_score is not None]
    return {
        "assessments": len(rows), "findings": len(findings),
        "findings_by_severity": by_sev, "assessments_by_status": by_status,
        "avg_risk": round(sum(scores) / len(scores), 2) if scores else None,
        "audit_events": audit.count(db),
        "emergency_stop": emergency_stop.state(db),
        "recent": [{"id": a.id, "name": a.name, "module": a.module, "status": a.status,
                    "risk": a.risk_score, "mode": a.mode,
                    "created_at": a.created_at.isoformat() if a.created_at else None} for a in rows[:10]],
    }
