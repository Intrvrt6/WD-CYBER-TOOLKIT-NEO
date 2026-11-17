"""Authentication and operator management endpoints."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from backend import authentication, emergency_stop
from backend.authentication import AuthError
from backend.database import User, get_db
from backend.deps import (Principal, bearer, current_principal, require_role,
                          require_stage2, require_stage2_role)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class StageOneIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512)
    shortcut: str = Field(min_length=1, max_length=128)


class StageTwoIn(BaseModel):
    pin: str = Field(min_length=1, max_length=64)


class PasswordIn(BaseModel):
    old_password: str
    new_password: str


class PinIn(BaseModel):
    password: str
    new_pin: str


@router.post("/stage1")
def stage1(body: StageOneIn, request: Request, db: OrmSession = Depends(get_db)):
    try:
        return authentication.stage_one(db, body.username, body.password, body.shortcut,
                                       ip=request.client.host if request.client else "",
                                       user_agent=request.headers.get("user-agent", ""))
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})


@router.post("/stage2")
def stage2(body: StageTwoIn, request: Request, token: str = Depends(bearer),
           db: OrmSession = Depends(get_db)):
    sess = authentication.session_from_token(db, token)
    if sess is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    try:
        result = authentication.stage_two(db, sess, body.pin,
                                          ip=request.client.host if request.client else "")
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})
    stop = emergency_stop.state(db)
    result["emergency_stop"] = stop
    return result


@router.get("/me")
def me(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    return {
        "user": {"id": p.user.id, "username": p.user.username, "role": p.user.role,
                 "must_change_password": p.user.must_change_password},
        "stage": p.stage,
        "session": {"id": p.session.id,
                    "expires_at": p.session.expires_at.isoformat() if p.session.expires_at else None,
                    "created_at": p.session.created_at.isoformat() if p.session.created_at else None},
        "emergency_stop": emergency_stop.state(db),
    }


@router.post("/logout")
def logout(p: Principal = Depends(current_principal), db: OrmSession = Depends(get_db)):
    p.session.revoked = True
    db.commit()
    from backend import audit
    audit.record("auth.logout", actor=p.username, detail={"session": p.session.id}, db=db)
    return {"ok": True}


@router.post("/password")
def change_password(body: PasswordIn, p: Principal = Depends(current_principal),
                    db: OrmSession = Depends(get_db)):
    try:
        return authentication.change_password(db, p.user, body.old_password, body.new_password,
                                             keep_session_id=p.session.id)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})


@router.post("/pin")
def change_pin(body: PinIn, p: Principal = Depends(require_stage2),
               db: OrmSession = Depends(get_db)):
    """Rotate the stage-2 PIN. Requires a stage-2 session.

    This used to accept any authenticated session plus the stage-1 password, so
    a stage-1-only holder could set a PIN of their choosing and then immediately
    satisfy stage 2 themselves - the second factor was self-serviceable.
    """
    try:
        return authentication.change_pin(db, p.user, body.password, body.new_pin,
                                        keep_session_id=p.session.id)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})


class OperatorIn(BaseModel):
    username: str
    password: str
    pin: str
    role: str = "operator"


@router.get("/operators")
def list_operators(p: Principal = Depends(require_role("admin")), db: OrmSession = Depends(get_db)):
    rows = db.execute(select(User).order_by(User.created_at)).scalars().all()
    now = dt.datetime.now(dt.timezone.utc)
    out = []
    for u in rows:
        locked = u.locked_until is not None and (u.locked_until if u.locked_until.tzinfo else u.locked_until.replace(tzinfo=dt.timezone.utc)) > now
        out.append({"id": u.id, "username": u.username, "role": u.role, "active": u.is_active,
                    "locked": locked, "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
                    "must_change_password": u.must_change_password})
    return {"operators": out}


@router.post("/operators")
def create_operator(body: OperatorIn, p: Principal = Depends(require_stage2_role("admin")),
                    db: OrmSession = Depends(get_db)):
    from backend import audit, security
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Operator already exists")
    problem = security.password_strength_problem(body.password)
    if problem:
        raise HTTPException(status_code=400, detail=problem)
    if body.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400, detail="role must be admin|operator|viewer")
    u = User(username=body.username, role=body.role,
             password_hash=security.hash_secret(body.password),
             pin_hash=security.hash_secret(body.pin), must_change_password=True)
    db.add(u)
    db.commit()
    audit.record("operator.created", actor=p.username, target=body.username,
                 detail={"role": body.role}, db=db)
    return {"id": u.id, "username": u.username, "role": u.role}


@router.post("/shortcuts")
def create_shortcut(label: str = "operator", p: Principal = Depends(require_stage2_role("admin")),
                    db: OrmSession = Depends(get_db)):
    """Rotate/issue a new stage-1 WD shortcut. Returned once, stored hashed."""
    import secrets, string
    from backend import audit, security
    from backend.database import Shortcut
    alphabet = string.ascii_uppercase + string.digits
    code = "WD-" + "".join(secrets.choice(alphabet) for _ in range(13))
    sc = Shortcut(code_hash=security.hash_secret(code), label=label)
    db.add(sc)
    db.commit()
    audit.record("shortcut.created", actor=p.username, target=label, detail={"id": sc.id}, db=db)
    return {"id": sc.id, "label": label, "shortcut": code,
            "note": "Shown once. Store it securely; only its Argon2id hash is persisted."}


@router.post("/unlock")
def unlock_after_stop(p: Principal = Depends(require_stage2_role("admin", "operator")), db: OrmSession = Depends(get_db)):
    """Clearing an emergency stop requires a fresh stage-2 session."""
    return emergency_stop.unlock(db, actor=p.username, reason="stage-2 re-authentication")
