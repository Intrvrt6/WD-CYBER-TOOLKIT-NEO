"""FastAPI dependencies: session resolution, stage enforcement, RBAC."""
from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session as OrmSession

from backend import authentication
from backend.authentication import AuthError
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


def require_role(*roles: str):
    def _dep(p: Principal = Depends(current_principal)) -> Principal:
        if p.role not in roles:
            raise HTTPException(status_code=403, detail=f"Requires role: {', '.join(roles)}")
        return p
    return _dep
