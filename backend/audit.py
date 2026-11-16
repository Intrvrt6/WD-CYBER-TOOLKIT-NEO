"""Tamper-evident audit log.

Each event is appended with seq = previous seq + 1 and
hash = sha256(prev_hash || canonical_json(event)). Any mutation of an earlier
row breaks every later hash, which `verify_chain()` detects.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
from typing import Any

from sqlalchemy import func, select

from backend.database import AuditEvent, SessionLocal, utcnow

GENESIS = "0" * 64


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _ts_repr(value) -> str:
    """Deterministic timestamp text.

    SQLite does not persist tzinfo, so a hash computed from a tz-aware
    datetime would not verify after a read-back. Normalise to UTC and format
    explicitly instead of relying on datetime.isoformat().
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if value.tzinfo is not None:
        value = value.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f")


def record(action: str, actor: str = "system", target: str = "", detail: dict | None = None,
           db=None) -> dict[str, Any]:
    own = db is None
    if own:
        db = SessionLocal()
    try:
        last = db.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)).scalar_one_or_none()
        seq = 1 if last is None else last.seq + 1
        prev_hash = GENESIS if last is None else last.hash
        ts = utcnow()
        body = {
            "seq": seq, "ts": _ts_repr(ts), "actor": actor, "action": action,
            "target": target, "detail": detail or {},
        }
        h = hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()
        ev = AuditEvent(seq=seq, ts=ts, actor=actor, action=action, target=target,
                        detail=detail or {}, prev_hash=prev_hash, hash=h)
        db.add(ev)
        db.commit()
        return {"seq": seq, "hash": h, "ts": ts.isoformat(), "action": action}
    finally:
        if own:
            db.close()


def list_events(db, limit: int = 200, action: str | None = None) -> list[dict[str, Any]]:
    q = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit)
    if action:
        q = select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.seq.desc()).limit(limit)
    return [_to_dict(e) for e in db.execute(q).scalars().all()]


def _to_dict(e: AuditEvent) -> dict[str, Any]:
    return {
        "seq": e.seq, "ts": e.ts.isoformat() if e.ts else None, "actor": e.actor,
        "action": e.action, "target": e.target, "detail": e.detail,
        "prev_hash": e.prev_hash, "hash": e.hash, "id": e.id,
    }


def export_json(db, limit: int = 10000) -> str:
    rows = [_to_dict(e) for e in db.execute(
        select(AuditEvent).order_by(AuditEvent.seq.asc()).limit(limit)).scalars().all()]
    return json.dumps({"events": rows, "count": len(rows)}, indent=2)


def export_csv(db, limit: int = 10000) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "ts", "actor", "action", "target", "detail", "prev_hash", "hash"])
    for e in db.execute(select(AuditEvent).order_by(AuditEvent.seq.asc()).limit(limit)).scalars().all():
        w.writerow([e.seq, e.ts.isoformat() if e.ts else "", e.actor, e.action, e.target,
                    json.dumps(e.detail, sort_keys=True, default=str), e.prev_hash, e.hash])
    return buf.getvalue()


def verify_chain(db) -> dict[str, Any]:
    events = db.execute(select(AuditEvent).order_by(AuditEvent.seq.asc())).scalars().all()
    prev = GENESIS
    expected_seq = 1
    for e in events:
        body = {"seq": e.seq, "ts": _ts_repr(e.ts), "actor": e.actor, "action": e.action,
                "target": e.target, "detail": e.detail or {}}
        recomputed = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
        if e.seq != expected_seq:
            return {"valid": False, "broken_at": e.seq, "reason": f"sequence gap, expected {expected_seq}"}
        if e.prev_hash != prev or e.hash != recomputed:
            return {"valid": False, "broken_at": e.seq, "reason": "hash mismatch"}
        prev = e.hash
        expected_seq += 1
    return {"valid": True, "events": len(events), "head": prev}


def count(db) -> int:
    return int(db.execute(select(func.count()).select_from(AuditEvent)).scalar_one())
