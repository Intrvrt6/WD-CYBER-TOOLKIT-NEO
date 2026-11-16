"""Tamper-evident audit log: append-only hash chain, exports, tamper detection."""
import json

from sqlalchemy import text

from backend import audit


def test_chain_is_valid_after_appends(db):
    for i in range(5):
        audit.record("test.event", actor="tester", target=f"t{i}", detail={"i": i}, db=db)
    v = audit.verify_chain(db)
    assert v["valid"] is True
    assert v["events"] == 5
    assert len(v["head"]) == 64


def test_chain_links_are_sequential_and_chained(db):
    for i in range(3):
        audit.record("test.link", actor="a", detail={"i": i}, db=db)
    events = audit.list_events(db, limit=10)
    by_seq = sorted(events, key=lambda e: e["seq"])
    assert [e["seq"] for e in by_seq] == [1, 2, 3]
    assert by_seq[0]["prev_hash"] == audit.GENESIS
    assert by_seq[1]["prev_hash"] == by_seq[0]["hash"]
    assert by_seq[2]["prev_hash"] == by_seq[1]["hash"]


def test_chain_survives_timezone_roundtrip(db):
    """The canonical hash must not depend on SQLite dropping tzinfo."""
    audit.record("test.tz", actor="a", db=db)
    v = audit.verify_chain(db)
    assert v["valid"] is True, v
    # force a fresh session read to be sure nothing is cached
    from backend.database import SessionLocal
    s2 = SessionLocal()
    try:
        assert audit.verify_chain(s2)["valid"] is True
    finally:
        s2.close()


def test_tampering_breaks_the_chain(db):
    for i in range(4):
        audit.record("test.tamper", actor="a", detail={"i": i}, db=db)
    assert audit.verify_chain(db)["valid"] is True
    db.execute(text("UPDATE audit_events SET actor='intruder' WHERE seq=2"))
    db.commit()
    v = audit.verify_chain(db)
    assert v["valid"] is False
    assert v["broken_at"] == 2


def test_deleting_an_event_breaks_the_chain(db):
    for i in range(4):
        audit.record("test.delete", actor="a", detail={"i": i}, db=db)
    db.execute(text("DELETE FROM audit_events WHERE seq=3"))
    db.commit()
    v = audit.verify_chain(db)
    assert v["valid"] is False
    assert v["broken_at"] == 4


def test_json_export_shape(db):
    audit.record("test.export", actor="a", db=db)
    payload = json.loads(audit.export_json(db))
    assert payload["count"] >= 1
    assert {"seq", "ts", "actor", "action", "target", "detail", "hash"} <= set(payload["events"][0])


def test_csv_export_has_header_and_rows(db):
    audit.record("test.csv", actor="a", db=db)
    csv_text = audit.export_csv(db)
    lines = [l for l in csv_text.strip().splitlines() if l]
    assert lines[0].startswith("seq,ts,actor,action")
    assert len(lines) >= 2


def test_count_and_filter(db):
    audit.record("test.alpha", actor="a", db=db)
    audit.record("test.beta", actor="a", db=db)
    assert audit.count(db) >= 2
    only = audit.list_events(db, limit=50, action="test.alpha")
    assert len(only) == 1 and only[0]["action"] == "test.alpha"
