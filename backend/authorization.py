"""Scope registry, target validation and per-assessment authorization tokens."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Any

from sqlalchemy import select

from backend import audit, config
from backend.database import Authorization, ScopeEntry, Session, User, utcnow


class ScopeError(Exception):
    def __init__(self, message: str, code: str = "SCOPE_ERROR", status: int = 400):
        super().__init__(message)
        self.message, self.code, self.status = message, code, status


DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")


def classify_target(target: str) -> str:
    t = target.strip()
    if t.lower().startswith(("can:", "vcan", "slcan", "socketcan")):
        return "can"
    if t.lower().startswith(("modbus://", "opcua://", "dnp3://", "enip://")):
        return "ics_endpoint"
    if t.startswith(("http://", "https://")):
        return "url"
    if CIDR_RE.match(t):
        try:
            ipaddress.ip_network(t, strict=False)
            return "cidr" if "/" in t else "ip"
        except ValueError:
            return "invalid"
    if DOMAIN_RE.match(t.lower()):
        return "domain"
    return "unknown"


def add_scope(db, target: str, target_type: str = "auto", description: str = "",
              created_by: str = "system") -> ScopeEntry:
    t = target.strip()
    tt = classify_target(t) if target_type in ("auto", "") else target_type
    if tt == "invalid":
        raise ScopeError(f"'{t}' is not a valid IP, CIDR, domain or URL")
    existing = db.execute(
        select(ScopeEntry).where(ScopeEntry.target == t, ScopeEntry.target_type == tt)
    ).scalar_one_or_none()
    if existing is not None:
        existing.active = True
        db.commit()
        return existing
    entry = ScopeEntry(target=t, target_type=tt, description=description, created_by=created_by)
    db.add(entry)
    db.commit()
    audit.record("scope.added", actor=created_by, target=t, detail={"type": tt}, db=db)
    return entry


def _url_origin(value: str) -> tuple[str, str, int] | None:
    """(scheme, host, port) for an absolute URL, or None when unparseable.

    ``urlparse(...).hostname`` also resolves userinfo and default ports, which is
    what matters: ``https://example.com@evil.tld/`` has host ``evil.tld`` even
    though the string *starts with* ``https://example.com``.
    """
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    if not parts.scheme or not parts.hostname:
        return None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    return (parts.scheme.lower(), parts.hostname.lower(), port)


def _cidr_contains(entry_target: str, target: str) -> bool:
    """True only when `target` is a network/host fully inside `entry_target`.

    Comparing the first address of the requested range (the previous behaviour)
    let a registered /24 cover a requested /8: 16.7M addresses out of scope but
    validated in scope. A requested range must be a subnet of the entry.
    """
    try:
        net = ipaddress.ip_network(entry_target, strict=False)
        req = ipaddress.ip_network(target.split("/")[0] if "/" not in target else target,
                                  strict=False)
    except ValueError:
        return False
    if "/" in target:
        return req.subnet_of(net)
    return req.network_address in net


def _matches(entry: ScopeEntry, target: str) -> bool:
    e = entry.target.strip()
    t = target.strip()
    if e == t:
        return True
    et = entry.target_type
    if et in ("cidr", "ip"):
        return _cidr_contains(e, t)
    if et == "domain":
        tl = t.lower()
        if tl.startswith(("http://", "https://")):
            origin = _url_origin(t)
            tl = origin[1] if origin else ""
        else:
            tl = tl.split("/", 1)[0].split(":", 1)[0]
        el = e.lower()
        return bool(tl) and (tl == el or tl.endswith("." + el))
    if et == "url":
        # Origin comparison, then a *path* prefix on that origin. A raw string
        # prefix accepted `https://example.com@evil.tld/` and
        # `https://example.com.evil.tld/` while the grant recorded only
        # `https://example.com`; and a bare origin comparison would have widened
        # `https://host/api` to the whole host.
        want, got = _url_origin(e), _url_origin(t)
        if want and got:
            same_origin = (want[0] == got[0] and want[2] == got[2]
                           and (got[1] == want[1] or got[1].endswith("." + want[1])))
            if not same_origin:
                return False
            from urllib.parse import urlsplit
            want_path = urlsplit(e).path or "/"
            got_path = urlsplit(t).path or "/"
            if want_path in ("", "/"):
                return True
            return got_path == want_path or got_path.startswith(want_path.rstrip("/") + "/")
        # A path-prefixed entry with no scheme keeps path semantics, but must not
        # be widened by a different host.
        if "/" in e and not want:
            return t.startswith(e)
        return False
    if et == "can":
        return t == e or t.startswith(e)
    if et == "ics_endpoint":
        return t.split("://")[-1] == e.split("://")[-1] or t == e
    return False


def validate_targets(db, targets: list[str]) -> dict[str, Any]:
    entries = db.execute(select(ScopeEntry).where(ScopeEntry.active.is_(True))).scalars().all()
    results = []
    all_ok = True
    for t in targets:
        hit = next((e for e in entries if _matches(e, t)), None)
        ok = hit is not None
        all_ok = all_ok and ok
        results.append({"target": t, "in_scope": ok,
                        "matched_scope": hit.target if hit else None,
                        "target_type": classify_target(t)})
    return {"all_in_scope": all_ok, "results": results,
            "scope_size": len(entries)}


def _norm(d: dt.datetime | None) -> dt.datetime | None:
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def create_authorization(db, user: User, sess: Session, targets: list[str],
                        ttl_minutes: int | None = None, note: str = "") -> Authorization:
    if sess.stage < 2:
        raise ScopeError("Stage-2 authentication required before authorizing a test.",
                         "STAGE2_REQUIRED", 403)
    if not targets:
        raise ScopeError("At least one target must be declared.")
    check = validate_targets(db, targets)
    out_of_scope = [r["target"] for r in check["results"] if not r["in_scope"]]
    if out_of_scope:
        raise ScopeError("Targets outside the registered scope: " + ", ".join(out_of_scope),
                         "OUT_OF_SCOPE", 403)
    ttl = min(ttl_minutes or config.AUTHZ_TTL_MINUTES, config.AUTHZ_MAX_TTL_MINUTES)
    authz = Authorization(
        user_id=user.id, targets=list(targets), scope_snapshot=check["results"],
        confirmed=True, expires_at=utcnow() + dt.timedelta(minutes=ttl), note=note,
    )
    db.add(authz)
    db.commit()
    audit.record("authz.granted", actor=user.username, target=",".join(targets),
                 detail={"authz": authz.id, "ttl_minutes": ttl, "note": note}, db=db)
    return authz


def assert_valid(db, authz_id: str | None, targets: list[str],
                 user_id: str | None = None) -> Authorization:
    """Validate an authorization for the stated targets.

    ``user_id`` is the operator about to run the test. When supplied, the
    authorization must have been granted to that operator: previously any
    authenticated operator could spend somebody else's authorization, so the
    audit trail attributed a run to whoever held the id.
    """
    if not authz_id:
        raise ScopeError("An explicit authorization is required to run a test.",
                         "NO_AUTHZ", 403)
    authz = db.get(Authorization, authz_id)
    if authz is None or not authz.confirmed:
        raise ScopeError("Authorization not found or unconfirmed.", "BAD_AUTHZ", 403)
    if authz.revoked:
        raise ScopeError("Authorization revoked.", "AUTHZ_REVOKED", 403)
    if user_id is not None and authz.user_id != user_id:
        raise ScopeError("This authorization was granted to a different operator.",
                         "AUTHZ_FOREIGN", 403)
    if (_norm(authz.expires_at) or utcnow()) < utcnow():
        raise ScopeError("Authorization expired.", "AUTHZ_EXPIRED", 403)
    check = validate_targets(db, targets)
    bad = [r["target"] for r in check["results"] if not r["in_scope"]]
    if bad:
        raise ScopeError("Targets outside registered scope: " + ", ".join(bad), "OUT_OF_SCOPE", 403)
    unauthorized = [t for t in targets if t not in (authz.targets or [])]
    if unauthorized:
        raise ScopeError("Targets not covered by this authorization: " + ", ".join(unauthorized),
                         "AUTHZ_TARGET_MISMATCH", 403)
    return authz


def revoke_all(db, reason: str = "emergency_stop") -> int:
    rows = db.execute(select(Authorization).where(Authorization.revoked.is_(False))).scalars().all()
    for a in rows:
        a.revoked = True
    db.commit()
    audit.record("authz.revoked_all", actor="system",
                 detail={"count": len(rows), "reason": reason}, db=db)
    return len(rows)


def pending_by_id(db, authz_id: str) -> dict | None:
    a = db.get(Authorization, authz_id)
    if a is None:
        return None
    return {"id": a.id, "targets": a.targets, "expires_at": _norm(a.expires_at).isoformat() if a.expires_at else None,
            "revoked": a.revoked, "confirmed": a.confirmed}
