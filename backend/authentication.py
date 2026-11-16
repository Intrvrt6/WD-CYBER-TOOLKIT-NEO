"""Two-stage WD access control.

Stage 1 - WD shortcut code + operator username/password.
Stage 2 - separate PIN, raising the session from stage 1 to stage 2.
Only stage-2 sessions may create authorizations or run assessments.
"""
from __future__ import annotations

import datetime as dt
import os
from typing import Any

from sqlalchemy import select

from backend import audit, config, security
from backend.database import Session, Shortcut, User, kv_get, kv_set, utcnow

RATE_KEY = "login_attempts"

# Stage-2 attempt ceiling: a 6-8 digit PIN is only 10^6-10^8 and, unlike the
# password, was previously not rate limited at all, so a stage-1 holder could
# simply iterate the PIN space on one session.
STAGE2_MAX_ATTEMPTS = int(os.environ.get("WD_STAGE2_MAX_ATTEMPTS", "5"))


def _naive_safe(value):
    """SQLite returns naive datetimes; treat them as UTC for comparison."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


class AuthError(Exception):
    def __init__(self, message: str, code: str = "AUTH_ERROR", status: int = 401):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


# ---------------------------------------------------------------- bootstrap --
def _random_password() -> str:
    # Memorable but high-entropy: 4 groups of 5 base32 chars + symbol + digit
    import secrets
    import string
    alphabet = string.ascii_uppercase + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4)]
    return "-".join(groups) + "!7"


def _random_pin() -> str:
    import secrets
    return f"{secrets.randbelow(10**8):08d}"


def _random_shortcut() -> str:
    import secrets
    import string
    alphabet = string.ascii_uppercase + string.digits
    return "WD-" + "".join(secrets.choice(alphabet) for _ in range(13))


def bootstrap(db) -> dict[str, Any] | None:
    """Create the first operator if none exists.

    Priority: explicit WD_ADMIN_* env values, otherwise auto-generate strong
    credentials and write them once to database/bootstrap_credentials.txt
    (mode 0600). Returns the cleartext dict exactly once, else None.
    """
    existing = db.execute(select(User).limit(1)).scalar_one_or_none()
    if existing is not None:
        return None

    username = config.BOOTSTRAP_USER or "WD-OPERATOR-01"
    password = config.BOOTSTRAP_PASSWORD or _random_password()
    pin = config.BOOTSTRAP_PIN or _random_pin()
    shortcut = config.BOOTSTRAP_SHORTCUT or _random_shortcut()

    if config.BOOTSTRAP_USER and not config.BOOTSTRAP_PASSWORD:
        raise AuthError("WD_ADMIN_USER set but WD_ADMIN_PASSWORD missing", "BOOTSTRAP_INCOMPLETE", 500)

    user = User(
        username=username, role="admin",
        password_hash=security.hash_secret(password),
        pin_hash=security.hash_secret(pin),
        must_change_password=config.FORCE_PASSWORD_CHANGE and not config.BOOTSTRAP_PASSWORD,
    )
    db.add(user)
    db.add(Shortcut(code_hash=security.hash_secret(shortcut), label="primary-operator"))
    db.commit()

    creds = {"username": username, "password": password, "pin": pin, "shortcut": shortcut,
             "must_change_password": user.must_change_password}
    config.ensure_dirs()
    path = config.DATA_DIR / "bootstrap_credentials.txt"
    path.write_text(
        "WD CYBER TOOLKIT NEO - one-time bootstrap credentials\n"
        "Generated: " + utcnow().isoformat() + "\n"
        "Delete this file after storing the values securely.\n\n"
        f"Operator username : {username}\n"
        f"Operator password : {password}\n"
        f"Stage-2 PIN       : {pin}\n"
        f"Stage-1 WD shortcut: {shortcut}\n",
        encoding="utf-8",
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    kv_set(db, "bootstrap_done", {"at": utcnow().isoformat(), "user": username})
    audit.record("auth.bootstrap", actor="system", target=username,
                 detail={"bootstrap_file": str(path)}, db=db)
    return creds


# ------------------------------------------------------------- rate limiting --
def _throttle(db, key: str, limit: int | None = None) -> None:
    """Sliding-window throttle, counted per key.

    The counter used to be one global row, so ten failed logins from any single
    source blocked *every* operator from authenticating: a trivial login DoS.
    Each key (client IP, and username) now keeps its own window, and the map is
    bounded so hostile key churn cannot grow state without limit.
    """
    now = utcnow()
    state = kv_get(db, RATE_KEY, {}) or {}
    windows = state.get("windows")
    if not isinstance(windows, dict):
        windows = {}  # tolerate the legacy single-window payload
    entry = windows.get(key) or {}
    window_start = entry.get("window_start")
    hits = int(entry.get("hits", 0))
    if window_start is None or (now - dt.datetime.fromisoformat(window_start)).total_seconds() > config.RATE_LIMIT_WINDOW_SECONDS:
        window_start, hits = now.isoformat(), 0
    allowed = config.RATE_LIMIT_ATTEMPTS if limit is None else limit
    if hits >= allowed:
        raise AuthError("Too many authentication attempts for this identity, slow down.",
                        "RATE_LIMITED", 429)
    windows[key] = {"window_start": window_start, "hits": hits + 1}
    if len(windows) > 2048:
        newest = sorted(windows.items(), key=lambda kv: kv[1].get("window_start") or "")[-1024:]
        windows = dict(newest)
    kv_set(db, RATE_KEY, {"windows": windows})


# ---------------------------------------------------------------- stage one --
def stage_one(db, username: str, password: str, shortcut: str, ip: str = "",
              user_agent: str = "") -> dict[str, Any]:
    # Per client address *and* per claimed username: one noisy source can no
    # longer exhaust the whole install's login budget, and distributed guessing
    # against a single account is still bounded.
    # The address budget is deliberately wider than the identity budget:
    # several operators legitimately share one NAT address, so one account's
    # failed logins must not block its colleagues, while a host still cannot
    # run unbounded guessing across many usernames.
    _throttle(db, f"stage1:ip:{ip or 'unknown'}", limit=config.RATE_LIMIT_ATTEMPTS * 10)
    _throttle(db, f"stage1:user:{(username or 'unknown').lower()}")
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()

    if user is not None and _naive_safe(user.locked_until) and _naive_safe(user.locked_until) > utcnow():
        raise AuthError(f"Account locked until {user.locked_until.isoformat()}", "LOCKED", 423)

    shortcut_ok = False
    for sc in db.execute(select(Shortcut).where(Shortcut.active.is_(True))).scalars().all():
        if security.verify_secret(sc.code_hash, shortcut):
            shortcut_ok = True
            matched_shortcut = sc
            break

    valid = user is not None and security.verify_secret(user.password_hash, password)

    if not (valid and shortcut_ok):
        if user is not None:
            user.failed_count += 1
            if user.failed_count >= config.MAX_LOGIN_FAILURES:
                user.locked_until = utcnow() + dt.timedelta(minutes=config.LOCKOUT_MINUTES)
                user.failed_count = 0
                audit.record("auth.lockout", actor=username, target=username,
                             detail={"minutes": config.LOCKOUT_MINUTES}, db=db)
            db.commit()
        audit.record("auth.stage1.failed", actor=username or "unknown", target=username,
                     detail={"shortcut_ok": shortcut_ok, "ip": ip, "reason":
                             "bad_shortcut" if valid else "bad_credentials"}, db=db)
        raise AuthError("Invalid WD shortcut or credentials.", "INVALID_CREDENTIALS", 401)

    assert user is not None
    token = security.new_token()
    sess = Session(
        token_hash=security.token_fingerprint(token), user_id=user.id,
        shortcut_id=matched_shortcut.id, stage=1, ip=ip, user_agent=user_agent[:256],
        expires_at=utcnow() + dt.timedelta(minutes=config.SESSION_TTL_MINUTES),
    )
    db.add(sess)
    user.failed_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    db.commit()
    audit.record("auth.stage1.ok", actor=user.username, target=user.username,
                 detail={"ip": ip, "session": sess.id}, db=db)
    return {"token": token, "stage": 1, "user": _user_dict(user),
            "expires_at": sess.expires_at.isoformat(),
            "next": "stage2: POST /api/auth/stage2 with the stage-2 PIN"}


# ---------------------------------------------------------------- stage two --
def stage_two(db, session: Session, pin: str, ip: str = "") -> dict[str, Any]:
    user = db.get(User, session.user_id)
    if user is None:
        raise AuthError("Session user missing", "NO_USER", 401)
    if _naive_safe(user.locked_until) and _naive_safe(user.locked_until) > utcnow():
        raise AuthError(f"Account locked until {user.locked_until.isoformat()}", "LOCKED", 423)
    _throttle(db, f"stage2:session:{session.id}")
    if not security.verify_secret(user.pin_hash, pin):
        fail_key = f"stage2_fail:{session.id}"
        state = kv_get(db, fail_key, {"hits": 0}) or {"hits": 0}
        hits = int(state.get("hits", 0)) + 1
        kv_set(db, fail_key, {"hits": hits})
        user.failed_count += 1
        locked = False
        if user.failed_count >= config.MAX_LOGIN_FAILURES:
            user.locked_until = utcnow() + dt.timedelta(minutes=config.LOCKOUT_MINUTES)
            user.failed_count = 0
            locked = True
            audit.record("auth.lockout", actor=user.username, target=user.username,
                         detail={"minutes": config.LOCKOUT_MINUTES, "stage": 2}, db=db)
        if hits >= STAGE2_MAX_ATTEMPTS:
            session.revoked = True
        db.commit()
        audit.record("auth.stage2.failed", actor=user.username, target=user.username,
                     detail={"ip": ip, "session": session.id, "attempt": hits,
                             "session_revoked": bool(session.revoked)}, db=db)
        if session.revoked:
            raise AuthError(f"Too many invalid PIN attempts ({hits}); session revoked, "
                            "start again at stage 1.", "PIN_ATTEMPTS_EXCEEDED", 423)
        if locked:
            raise AuthError(f"Account locked until {user.locked_until.isoformat()}", "LOCKED", 423)
        raise AuthError("Invalid stage-2 PIN.", "INVALID_PIN", 401)
    session.stage = 2
    user.failed_count = 0
    kv_set(db, f"stage2_fail:{session.id}", {"hits": 0})
    db.commit()
    audit.record("auth.stage2.ok", actor=user.username, target=user.username,
                 detail={"ip": ip, "session": session.id}, db=db)
    return {"stage": 2, "user": _user_dict(user),
            "message": "Stage 2 complete. Authorizations may now be created."}


def _user_dict(u: User) -> dict[str, Any]:
    return {"id": u.id, "username": u.username, "role": u.role,
            "must_change_password": u.must_change_password, "is_active": u.is_active}


# ------------------------------------------------------------------ resolve --
def session_from_token(db, token: str) -> Session | None:
    fp = security.token_fingerprint(token)
    sess = db.execute(select(Session).where(Session.token_hash == fp)).scalar_one_or_none()
    if sess is None or sess.revoked:
        return None
    exp = sess.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=dt.timezone.utc)
    if exp < utcnow():
        return None
    return sess


def revoke_all(db, reason: str = "emergency_stop") -> int:
    rows = db.execute(select(Session).where(Session.revoked.is_(False))).scalars().all()
    for s in rows:
        s.revoked = True
    db.commit()
    audit.record("auth.sessions.revoked", actor="system", detail={"count": len(rows), "reason": reason}, db=db)
    return len(rows)


# ---------------------------------------------------------------- passwords --
def change_password(db, user: User, old: str, new: str) -> dict[str, Any]:
    if not security.verify_secret(user.password_hash, old):
        raise AuthError("Current password incorrect.", "BAD_PASSWORD", 401)
    problem = security.password_strength_problem(new)
    if problem:
        raise AuthError(problem, "WEAK_PASSWORD", 400)
    user.password_hash = security.hash_secret(new)
    user.must_change_password = False
    db.commit()
    audit.record("auth.password.changed", actor=user.username, target=user.username, db=db)
    return {"ok": True}


def change_pin(db, user: User, password: str, new_pin: str) -> dict[str, Any]:
    if not security.verify_secret(user.password_hash, password):
        raise AuthError("Password required to rotate PIN.", "BAD_PASSWORD", 401)
    if not new_pin.isdigit() or len(new_pin) < 6:
        raise AuthError("PIN must be at least 6 digits.", "WEAK_PIN", 400)
    user.pin_hash = security.hash_secret(new_pin)
    db.commit()
    audit.record("auth.pin.changed", actor=user.username, target=user.username, db=db)
    return {"ok": True}
