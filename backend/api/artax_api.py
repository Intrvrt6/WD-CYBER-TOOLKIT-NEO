"""Artax AI endpoints: status, ask, streaming ask, and assessment-scoped analysis."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from backend import audit, capabilities, emergency_stop
from backend.artax import build_assessment_context, get_client
from backend.artax.client import ArtaxError
from backend.artax.prompts import build_platform_context
from backend.database import Artifact, Assessment, get_db
from backend.deps import (Principal, current_principal, ensure_assessment_access)
from backend.orchestrator import assessment_dict, findings_for

router = APIRouter(prefix="/api/artax", tags=["artax"])


class AskIn(BaseModel):
    question: str = Field(min_length=1, max_length=8000)
    assessment_id: str | None = None
    history: list[dict[str, Any]] = Field(default_factory=list)
    scope: str = Field(default="auto", pattern="^(auto|assessment|platform)$")


@router.get("/status")
def status(p: Principal = Depends(current_principal)):
    """Which Artax mode is live. The UI shows this so an answer is never mislabelled."""
    return get_client().status()


@router.get("/ping")
def ping(p: Principal = Depends(current_principal)):
    """Prove the configured endpoint actually answers (not just that a URL is set)."""
    client = get_client()
    if client.mode != "endpoint":
        return {"mode": client.mode, "ok": True,
                "note": "local evidence-only analyst; no endpoint to ping"}
    try:
        r = client.ask("Reply with the single word: ready", "")
        return {"mode": "endpoint", "ok": True, "model": r.get("model"),
                "reply": r.get("answer", "")[:120]}
    except ArtaxError as exc:
        raise HTTPException(status_code=exc.status,
                            detail={"code": exc.code, "message": exc.message})


def _context_for(db: OrmSession, assessment_id: str | None, scope: str,
                 principal: Principal) -> tuple[str, str]:
    """Build the evidence block. Returns (context, resolved_scope)."""
    if scope == "platform":
        from engines import base
        health_like = {"instance": "WD CYBER TOOLKIT NEO", "version": __import__(
            "backend.config", fromlist=["APP_VERSION"]).APP_VERSION,
            "engines": {"registered": base.modules(), "failed": {}},
            "emergency_stop": emergency_stop.state(db)}
        return build_platform_context(health_like, {"modules": base.module_catalog()},
                                      capabilities.report()), "platform"

    if assessment_id:
        a = db.get(Assessment, assessment_id)
        if a is None:
            raise HTTPException(status_code=404, detail="assessment not found")
        ensure_assessment_access(a, principal)
        arts = db.execute(select(Artifact).where(Artifact.assessment_id == assessment_id)).scalars().all()
        ctx = build_assessment_context(
            assessment_dict(a), findings_for(db, assessment_id),
            artifacts=[{"name": x.name, "kind": x.kind, "size": x.size, "sha256": x.sha256}
                       for x in arts])
        return ctx, "assessment"

    # scope=auto with no id: fall back to the most recent assessment, else platform.
    latest = db.execute(select(Assessment).order_by(Assessment.created_at.desc()).limit(1)).scalar_one_or_none()
    if latest is not None:
        arts = db.execute(select(Artifact).where(Artifact.assessment_id == latest.id)).scalars().all()
        ctx = build_assessment_context(
            assessment_dict(latest), findings_for(db, latest.id),
            artifacts=[{"name": x.name, "kind": x.kind, "size": x.size, "sha256": x.sha256}
                       for x in arts])
        return ctx, "assessment"
    return _context_for(db, None, "platform", principal)


@router.post("/ask")
def ask(body: AskIn, p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    context, resolved = _context_for(db, body.assessment_id, body.scope, p)
    client = get_client()
    try:
        result = client.ask(body.question, context, history=body.history[-10:])
    except ArtaxError as exc:
        raise HTTPException(status_code=exc.status,
                            detail={"code": exc.code, "message": exc.message})
    audit.record("artax.ask", actor=p.username, target=body.assessment_id or resolved,
                 detail={"scope": resolved, "parser": result.get("parser"),
                         "chars": len(result.get("answer", ""))}, db=db)
    return {**result, "scope": resolved, "mode": client.mode}


@router.post("/stream")
def stream(body: AskIn, p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    context, resolved = _context_for(db, body.assessment_id, body.scope, p)
    client = get_client()

    def gen():
        try:
            for chunk in client.stream(body.question, context):
                yield chunk
        except ArtaxError as exc:
            yield f"\n[artax error: {exc.code}] {exc.message}"

    audit.record("artax.stream", actor=p.username, target=body.assessment_id or resolved,
                 detail={"scope": resolved}, db=db)
    return StreamingResponse(gen(), media_type="text/plain; charset=utf-8",
                             headers={"x-artax-scope": resolved, "x-artax-mode": client.mode})


# ---------------------------------------------------------------- presets ----
PRESETS = {
    "executive_summary": "Write a concise executive summary of this assessment for a non-technical "
                         "stakeholder: business impact first, then the top 3 priorities. Note any "
                         "check that did not run.",
    "remediation_plan": "Produce a prioritised remediation plan: order by severity and exploitability, "
                        "group related findings, and give one concrete action per group.",
    "coverage_review": "Which checks did not report or returned 'unavailable', and what capability is "
                       "missing for each? Treat them as NOT TESTED, not as passes.",
    "attack_paths": "Based only on the recorded findings, describe plausible attack paths and which "
                    "asset is the most valuable next target. Do not invent services.",
    "report_review": "Review this assessment for weaknesses: thin coverage, low confidence evidence, "
                     "lab-vs-live confusion, or findings that need retesting.",
}


@router.get("/presets")
def presets(p: Principal = Depends(current_principal)):
    return {"presets": [{"id": k, "prompt": v} for k, v in PRESETS.items()]}


@router.post("/preset/{preset_id}")
def run_preset(preset_id: str, assessment_id: str | None = None,
               p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    if preset_id not in PRESETS:
        raise HTTPException(status_code=404, detail=f"unknown preset; try: {', '.join(PRESETS)}")
    context, resolved = _context_for(db, assessment_id, "auto", p)
    client = get_client()
    try:
        result = client.ask(PRESETS[preset_id], context)
    except ArtaxError as exc:
        raise HTTPException(status_code=exc.status,
                            detail={"code": exc.code, "message": exc.message})
    audit.record("artax.preset", actor=p.username, target=assessment_id or resolved,
                 detail={"preset": preset_id, "parser": result.get("parser")}, db=db)
    return {**result, "preset": preset_id, "scope": resolved, "mode": client.mode}
