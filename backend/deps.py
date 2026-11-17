"""FastAPI dependencies: session resolution, stage enforcement, RBAC."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session as OrmSession

from backend import authentication
from backend.database import Session, User, get_db


class Principal:
    def __init__(self, user: User, session: Session):
        self.user = user
        self.session = session

    @property
    def username(self) -> str:
        return self.user.username

    @property
    def stage(self) -> int:
        return self.session.stage

    @property
    def role(self) -> str:
        return self.user.role


def bearer(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def current_principal(token: str = Depends(bearer), db: OrmSession = Depends(get_db)) -> Principal:
    sess = authentication.session_from_token(db, token)
    if sess is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    user = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Operator inactive")
    return Principal(user, sess)


def require_stage2(p: Principal = Depends(current_principal)) -> Principal:
    if p.stage < 2:
        raise HTTPException(status_code=403, detail={
            "code": "STAGE2_REQUIRED",
            "message": "Stage-2 PIN verification required for this operation.",
        })
    return p


def require_stage2_fresh_password(p: Principal = Depends(require_stage2)) -> Principal:
    """Stage-2 gate that also refuses a session still holding a generated password.

    `must_change_password` is set on every bootstrap install so a shared or
    printed one-time password cannot be used for real work. Advertising the flag
    in /api/auth/me was not enough: nothing stopped an operator from running
    assessments with it, so the documented "forces a first-login rotation" did
    not hold. 428 is returned (not 403) because the fix is a further step the
    caller can take, and the frontend turns it into the rotation prompt.
    """
    if p.user.must_change_password:
        raise HTTPException(status_code=428, detail={
            "code": "PASSWORD_CHANGE_REQUIRED",
            "message": "Change the bootstrap password before authorizing or executing tests.",
        })
    return p


def require_stage2_role(*roles: str):
    """Role check *and* the stage-2 / rotated-password gates.

    `require_role` only looks at the user row, so a stage-1 viewer could reach any
    route that used it for RBAC alone; the execution routes need both.
    """
    def _dep(p: Principal = Depends(require_stage2_fresh_password)) -> Principal:
        if p.role not in roles:
            raise HTTPException(status_code=403, detail={
                "code": "ROLE_REQUIRED",
                "message": f"Requires role: {', '.join(roles)}"})
        return p
    return _dep


def require_role(*roles: str):
    def _dep(p: Principal = Depends(current_principal)) -> Principal:
        if p.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {', '.join(roles)}")
        return p
    return _dep



def ensure_assessment_access(assessment, principal: Principal) -> None:
    """Operators may read their own assessments; admins/viewers may browse all.

    Return 404 for foreign operator-owned records to avoid leaking whether an
    assessment identifier exists.
    """
    if principal.role in {"admin", "viewer"} or assessment.operator == principal.username:
        return
    raise HTTPException(status_code=404, detail="assessment not found")


def ensure_job_access(db: OrmSession, job_id: str, principal: Principal):
    from backend.database import Assessment, Job

    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    assessment = db.get(Assessment, job.assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="job not found")
    ensure_assessment_access(assessment, principal)
    return job
