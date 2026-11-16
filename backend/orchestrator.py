"""Assessment engine: preflight -> authorized execution -> evidence -> findings -> risk."""
from __future__ import annotations

import os
import threading
import time
from typing import Any

from sqlalchemy import select

from backend import audit, authorization, config, emergency_stop, runner, templates_registry
from backend.database import (
    Artifact, Assessment, Finding, Job, SessionLocal, User, utcnow,
)
from engines.base import Context, Result, get_engine, module_catalog

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.0}

_JOBS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()
_MAX_LOG_LINES = 500
_MAX_LIVE_MESSAGES = 200


# --------------------------------------------------------------- preflight --
def preflight(template: dict, targets: list[str], mode: str, params: dict) -> dict[str, Any]:
    checks = []
    ok = True
    if not targets:
        checks.append({"id": "PF-TARGET", "ok": False, "detail": "No targets supplied."})
        ok = False
    if template.get("module") not in module_catalog_modules():
        checks.append({"id": "PF-MODULE", "ok": False,
                       "detail": f"Engine for module '{template.get('module')}' is not loaded."})
        ok = False
    for item in template.get("preflight", []):
        checks.append({"id": item.get("id"), "ok": True,
                       "detail": f"Acknowledged: {item.get('question')}",
                       "required": item.get("required", True)})
    checks.append({"id": "PF-MODE", "ok": mode in ("live", "lab"),
                   "detail": f"Execution mode '{mode}' is {'valid' if mode in ("live","lab") else 'invalid'}."})
    if mode not in ("live", "lab"):
        ok = False
    checks.append({"id": "PF-PARAMS", "ok": True,
                   "detail": f"{len(params)} parameter(s) supplied; template defaults merged."})
    return {"ok": ok, "checks": checks}


def module_catalog_modules() -> list[str]:
    return [m["module"] for m in module_catalog()]


# ------------------------------------------------------------ assessment RK --
def create_assessment(db, user: User, name: str, template_id: str, targets: list[str],
                      mode: str | None = None, intensity: str | None = None,
                      params: dict | None = None) -> dict[str, Any]:
    tpl = templates_registry.get(template_id)
    merged = dict(tpl.get("params") or {})
    merged.update(params or {})
    mode = mode or tpl.get("mode_default") or "live"
    intensity = intensity or (tpl.get("intensity_options") or ["normal"])[0]
    pre = preflight(tpl, targets, mode, merged)
    a = Assessment(
        name=name or f"{tpl.get('name')} {utcnow().strftime('%Y-%m-%d %H:%M')}",
        template=template_id, module=tpl.get("module"), mode=mode, intensity=intensity,
        targets=list(targets), params=merged, status="created" if pre["ok"] else "preflight_failed",
        operator=user.username if user else "system",
    )
    db.add(a)
    db.commit()
    audit.record("assessment.created", actor=a.operator, target=",".join(targets),
                 detail={"assessment": a.id, "template": template_id, "mode": mode,
                         "intensity": intensity, "preflight_ok": pre["ok"]}, db=db)
    return {**assessment_dict(a), "preflight": pre, "template_detail": tpl.get("name")}


def assessment_dict(a: Assessment) -> dict[str, Any]:
    return {
        "id": a.id, "name": a.name, "template": a.template, "module": a.module,
        "mode": a.mode, "intensity": a.intensity, "targets": a.targets, "params": a.params,
        "status": a.status, "operator": a.operator, "risk_score": a.risk_score,
        "summary": a.summary or {},
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "started_at": a.started_at.isoformat() if a.started_at else None,
        "ended_at": a.ended_at.isoformat() if a.ended_at else None,
    }


# -------------------------------------------------------------- job runner --
def start_job(db, assessment: Assessment, authz_id: str, actor: str,
              user: User | None = None) -> dict[str, Any]:
    emergency_stop.require_clear(db)
    authorization.assert_valid(db, authz_id, list(assessment.targets or []),
                               user_id=user.id if user is not None else None)
    job = Job(assessment_id=assessment.id, status="queued")
    db.add(job)
    assessment.authz_id = authz_id
    assessment.status = "queued"
    db.commit()
    audit.record("assessment.queued", actor=actor, target=",".join(assessment.targets or []),
                 detail={"assessment": assessment.id, "job": job.id, "authz": authz_id}, db=db)
    t = threading.Thread(target=_run_job, args=(job.id, assessment.id), daemon=True)
    with _LOCK:
        _JOBS[job.id] = {"thread": t}
    t.start()
    return {"job_id": job.id, "assessment_id": assessment.id, "status": "queued"}


def _log(db, job: Job, level: str, message: str) -> None:
    """Append a structured log line (bounded) and mirror it to the live buffer."""
    log = list(job.log or [])
    log.append({"at": utcnow().isoformat(), "level": level, "message": message[:2000]})
    job.log = log[-_MAX_LOG_LINES:]
    db.commit()
    with _LOCK:
        entry = _JOBS.get(job.id)
        if entry is not None:
            buf = entry.setdefault("messages", [])
            buf.append(log[-1])
            if len(buf) > _MAX_LIVE_MESSAGES:
                del buf[:-_MAX_LIVE_MESSAGES]


def _drop_job(job_id: str) -> None:
    """Release the in-memory job entry once it has finished.

    Without this the registry kept a Thread object and its message buffer for
    every job ever run, which grows without bound in a long-lived process.
    """
    with _LOCK:
        _JOBS.pop(job_id, None)


def _run_job(job_id: str, assessment_id: str) -> None:
    db = SessionLocal()
    started = time.time()
    try:
        job = db.get(Job, job_id)
        a = db.get(Assessment, assessment_id)
        if job is None or a is None:
            return
        job.status = "running"
        a.status = "running"
        a.started_at = utcnow()
        db.commit()
        _log(db, job, "info", f"Starting {a.module} engine for {a.template} (mode={a.mode}, intensity={a.intensity})")

        if emergency_stop.is_active(db):
            raise RuntimeError("emergency stop active")

        evidence_dir = os.path.join(str(config.EVIDENCE_DIR), a.id)
        os.makedirs(evidence_dir, exist_ok=True)
        engine = get_engine(a.module)
        ctx = Context(
            assessment_id=a.id, module=a.module, mode=a.mode, intensity=a.intensity,
            targets=list(a.targets or []), params=dict(a.params or {}), evidence_dir=evidence_dir,
            log=lambda lvl, msg: _log(db, job, lvl, msg),
            progress=lambda pct: _set_progress(db, job, pct),
        )
        results = engine.run(ctx)

        saved = []
        for r in results:
            f = Finding(
                assessment_id=a.id, title=r.title, severity=r.severity,
                description=(r.description or "")[:8000], evidence_source=r.source,
                cvss_score=r.cvss_score, cvss_vector=r.cvss_vector, cwe=list(r.cwe or []),
                remediation=(r.remediation or "")[:4000], asset=(r.asset or "")[:250],
                evidence=r.evidence or [], check_id=r.check_id,
            )
            db.add(f)
            saved.append(f)
        db.commit()

        for ev in _collect_artifacts(results, evidence_dir, a.id):
            db.add(Artifact(**ev))
        db.commit()

        worst = max((SEVERITY_ORDER.get(r.severity, 0) for r in results), default=0)
        fail_like = [r for r in results if r.status in ("fail", "error")]
        risk = compute_risk(results)
        a.risk_score = risk
        a.summary = {
            "findings": len(results), "failed": len(fail_like),
            "unavailable": len([r for r in results if r.status == "unavailable"]),
            "worst_severity": [k for k, v in SEVERITY_ORDER.items() if v == worst][0],
            "by_severity": _count_by_severity(results),
            "by_status": _count_by(results, "status"),
            "by_source": _count_by(results, "source"),
            "duration_s": round(time.time() - started, 2),
            "checks_expected": [c[0] for c in engine.checks],
            "checks_reported": sorted({r.check_id for r in results}),
        }
        a.status = "aborted" if runner.executor.stopped() else "completed"
        a.ended_at = utcnow()
        job.status = "completed" if a.status == "completed" else "aborted"
        job.progress = 100
        job.ended_at = utcnow()
        db.commit()
        _log(db, job, "info", f"Completed with {len(results)} result(s); risk score {risk:.1f}")
        audit.record("assessment.completed", actor=a.operator, target=",".join(a.targets or []),
                     detail={"assessment": a.id, "job": job.id, "findings": len(results),
                             "risk": risk, "worst": a.summary["worst_severity"]}, db=db)
    except Exception as exc:
        try:
            job = db.get(Job, job_id)
            a = db.get(Assessment, assessment_id)
            if job is not None:
                job.status = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
                job.ended_at = utcnow()
            if a is not None:
                a.status = "failed"
                a.ended_at = utcnow()
            db.commit()
            _log(db, job, "error", f"Execution failed: {type(exc).__name__}: {exc}")
            audit.record("assessment.failed", actor=a.operator if a else "system",
                         detail={"assessment": assessment_id, "error": str(exc)[:500]}, db=db)
        except Exception:
            pass
    finally:
        db.close()
        _drop_job(job_id)


def _set_progress(db, job: Job, pct: int) -> None:
    job.progress = max(0, min(100, int(pct)))
    db.commit()


def _count_by(results: list[Result], attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        k = str(getattr(r, attr, "?"))
        out[k] = out.get(k, 0) + 1
    return out


def _count_by_severity(results: list[Result]) -> dict[str, int]:
    return _count_by(results, "severity")


def compute_risk(results: list[Result]) -> float:
    """Risk = weighted mean of scored findings, amplified by breadth of failures."""
    scored = [SEVERITY_SCORE.get(r.severity, 0.0) for r in results
              if r.status in ("fail", "error") and r.severity != "info"]
    if not scored:
        return 0.0
    base = sum(scored) / len(scored)
    breadth = min(1.0, len(scored) / 8.0)
    return round(min(10.0, base * (0.75 + 0.25 * breadth) + 0.5 * len([s for s in scored if s >= 8.0])), 2)


def _collect_artifacts(results: list[Result], evidence_dir: str, assessment_id: str) -> list[dict]:
    seen: set[str] = set()
    out = []
    for r in results:
        for ev in (r.evidence or []):
            if not isinstance(ev, dict):
                continue
            p = ev.get("path")
            if p and isinstance(p, str) and os.path.exists(p) and p not in seen:
                seen.add(p)
                out.append({
                    "assessment_id": assessment_id, "name": ev.get("name") or os.path.basename(p),
                    "path": p, "kind": ev.get("kind", "file"),
                    "size": int(ev.get("size") or os.path.getsize(p)),
                    "sha256": ev.get("sha256", ""),
                })
    return out


def job_state(db, job_id: str) -> dict[str, Any] | None:
    job = db.get(Job, job_id)
    if job is None:
        return None
    return {"id": job.id, "assessment_id": job.assessment_id, "status": job.status,
            "progress": job.progress, "log": job.log or [], "error": job.error,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "ended_at": job.ended_at.isoformat() if job.ended_at else None}


def findings_for(db, assessment_id: str) -> list[dict[str, Any]]:
    rows = db.execute(select(Finding).where(Finding.assessment_id == assessment_id)
                      .order_by(Finding.created_at.asc())).scalars().all()
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = sorted(rows, key=lambda f: (sev_rank.get(f.severity, 9), f.check_id))
    return [{"id": f.id, "check_id": f.check_id, "title": f.title, "severity": f.severity,
             "status": "fail" if f.severity not in ("info",) else "info",
             "description": f.description, "evidence_source": f.evidence_source,
             "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector, "cwe": f.cwe,
             "remediation": f.remediation, "asset": f.asset, "evidence": f.evidence,
             "created_at": f.created_at.isoformat() if f.created_at else None} for f in rows]
