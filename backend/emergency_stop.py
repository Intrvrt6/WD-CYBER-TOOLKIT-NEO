"""Global emergency stop.

Server-side authority: cancels jobs, aborts managed subprocesses, revokes
assessments and authorizations, and blocks new execution until a fresh
stage-1 + stage-2 authentication unlocks it. Frontend state is irrelevant.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select

from backend import audit, authorization, authentication, runner
from backend.database import Assessment, Job, kv_get, kv_set, utcnow

STOP_KEY = "emergency_stop"


def state(db) -> dict[str, Any]:
    s = kv_get(db, STOP_KEY, {"active": False, "generation": 0}) or {}
    s.setdefault("active", False)
    s.setdefault("generation", 0)
    return s


def is_active(db) -> bool:
    return bool(state(db).get("active"))


def generation(db) -> int:
    try:
        return int(state(db).get("generation", 0))
    except (TypeError, ValueError):
        return 0


def activate(db, actor: str = "operator", reason: str = "manual emergency stop") -> dict[str, Any]:
    s = state(db)
    if s.get("active"):
        return {"already_active": True, **s}

    gen = generation(db) + 1
    kv_set(db, STOP_KEY, {"active": True, "generation": gen, "activated_at": utcnow().isoformat(),
                          "activated_by": actor, "reason": reason})
    runner.executor.request_stop()

    jobs = db.execute(select(Job).where(Job.status.in_(("queued", "running")))).scalars().all()
    for j in jobs:
        j.status = "aborted"
        j.ended_at = utcnow()
        j.error = j.error or "aborted by emergency stop"
        log = list(j.log or [])
        log.append({"at": utcnow().isoformat(), "level": "error", "message": "aborted by emergency stop"})
        j.log = log
    db.commit()

    assessments = db.execute(
        select(Assessment).where(Assessment.status.in_(("running", "queued", "created")))
    ).scalars().all()
    for a in assessments:
        a.status = "aborted"
        a.ended_at = utcnow()
    db.commit()

    revoked_authz = authorization.revoke_all(db, reason="emergency_stop")
    revoked_sessions = authentication.revoke_all(db, reason="emergency_stop")

    audit.record("emergency_stop.activated", actor=actor, target="platform",
                 detail={"generation": gen, "reason": reason, "jobs_aborted": len(jobs),
                         "assessments_aborted": len(assessments),
                         "authz_revoked": revoked_authz,
                         "sessions_revoked": revoked_sessions}, db=db)
    return {"active": True, "generation": gen, "jobs_aborted": len(jobs),
            "assessments_aborted": len(assessments),
            "authorizations_revoked": revoked_authz, "sessions_revoked": revoked_sessions}


def unlock(db, actor: str, reason: str = "operator re-authenticated") -> dict[str, Any]:
    """Clear the stop after a fresh stage-2 authentication."""
    s = state(db)
    if not s.get("active"):
        return {"active": False, "message": "emergency stop was not active"}
    runner.executor.reset()
    s.update({"active": False, "cleared_at": utcnow().isoformat(), "cleared_by": actor,
              "clear_reason": reason})
    kv_set(db, STOP_KEY, s)
    audit.record("emergency_stop.cleared", actor=actor, target="platform",
                 detail={"generation": s.get("generation"), "reason": reason}, db=db)
    return {"active": False, "generation": s.get("generation")}


def require_clear(db) -> None:
    if is_active(db):
        from backend.authorization import ScopeError
        raise ScopeError("Emergency stop is active: re-authenticate and unlock before executing.",
                         "EMERGENCY_STOP", 423)
