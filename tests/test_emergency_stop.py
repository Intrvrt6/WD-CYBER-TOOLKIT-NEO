"""Emergency stop: subprocess abort, job/assessment cancellation, authz revocation, gate."""
import threading
import time

import pytest

from backend import authentication, authorization, emergency_stop, runner
from backend.authorization import ScopeError
from backend.database import Assessment, Authorization, Job, Session, User


def _seed(db):
    c = authentication.bootstrap(db)
    r = authentication.stage_one(db, c["username"], c["password"], c["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    authentication.stage_two(db, sess, c["pin"])
    u = db.query(User).first()
    authorization.add_scope(db, "example.com", created_by="t")
    a = authorization.create_authorization(db, u, sess, ["example.com"])
    ass = Assessment(name="stop test", template="network_pentest", module="network",
                     mode="live", targets=["example.com"], status="running", operator=u.username)
    db.add(ass); db.commit()
    job = Job(assessment_id=ass.id, status="running")
    db.add(job); db.commit()
    return c, a, ass, job


def test_activate_is_idempotent_and_generation_increments(db):
    runner.executor.reset()
    assert emergency_stop.is_active(db) is False
    r1 = emergency_stop.activate(db, actor="tester", reason="test")
    assert r1["active"] is True and r1["generation"] == 1
    r2 = emergency_stop.activate(db, actor="tester", reason="again")
    assert r2.get("already_active") is True
    assert emergency_stop.generation(db) == 1
    runner.executor.reset()
    emergency_stop.unlock(db, actor="tester")


def test_activate_aborts_jobs_and_assessments(db):
    runner.executor.reset()
    c, authz, ass, job = _seed(db)
    out = emergency_stop.activate(db, actor="tester", reason="unit")
    assert out["jobs_aborted"] >= 1
    assert out["assessments_aborted"] >= 1
    db.expire_all()
    assert db.get(Job, job.id).status == "aborted"
    assert db.get(Assessment, ass.id).status == "aborted"
    emergency_stop.unlock(db, actor="tester")


def test_activate_revokes_authorizations_and_sessions(db):
    runner.executor.reset()
    c, authz, ass, job = _seed(db)
    out = emergency_stop.activate(db, actor="tester", reason="unit")
    assert out["authorizations_revoked"] >= 1
    assert out["sessions_revoked"] >= 1
    db.expire_all()
    assert db.get(Authorization, authz.id).revoked is True
    assert all(s.revoked for s in db.query(Session).all())
    emergency_stop.unlock(db, actor="tester")


def test_require_clear_blocks_execution(db):
    runner.executor.reset()
    emergency_stop.activate(db, actor="tester", reason="block")
    with pytest.raises(ScopeError) as exc:
        emergency_stop.require_clear(db)
    assert exc.value.code == "EMERGENCY_STOP"
    emergency_stop.unlock(db, actor="tester")
    emergency_stop.require_clear(db)  # must not raise


def test_clear_requires_explicit_unlock(db):
    runner.executor.reset()
    emergency_stop.activate(db, actor="tester", reason="x")
    out = emergency_stop.unlock(db, actor="tester")
    assert out["active"] is False
    assert emergency_stop.is_active(db) is False


def test_stop_blocks_new_subprocess_execution(db):
    runner.executor.reset()
    ok = runner.run(["echo", "hello"])
    assert ok.ok and "hello" in ok.stdout
    runner.executor.request_stop()
    blocked = runner.run(["echo", "hello"])
    assert "emergency stop" in blocked.stderr.lower()
    assert blocked.returncode != 0
    runner.executor.reset()
    assert runner.run(["echo", "again"]).ok


def test_stop_kills_a_long_running_subprocess(db):
    runner.executor.reset()
    result = {}

    def long_proc():
        result["r"] = runner.run(["sleep", "30"], timeout=60)

    t = threading.Thread(target=long_proc)
    t.start()
    time.sleep(0.7)
    started = time.time()
    runner.executor.request_stop()
    t.join(timeout=15)
    elapsed = time.time() - started
    assert not t.is_alive(), "subprocess was not terminated by emergency stop"
    assert elapsed < 10
    assert result["r"].returncode != 0
    runner.executor.reset()


def test_stop_state_persists_across_sessions(db):
    runner.executor.reset()
    emergency_stop.activate(db, actor="tester", reason="persist")
    from backend.database import SessionLocal
    other = SessionLocal()
    try:
        assert emergency_stop.is_active(other) is True
    finally:
        other.close()
    emergency_stop.unlock(db, actor="tester")


def test_stop_is_recorded_in_audit(db):
    from backend import audit
    runner.executor.reset()
    emergency_stop.activate(db, actor="tester", reason="audit-check")
    events = audit.list_events(db, limit=50, action="emergency_stop.activated")
    assert events and events[0]["detail"]["reason"] == "audit-check"
    emergency_stop.unlock(db, actor="tester")
    cleared = audit.list_events(db, limit=50, action="emergency_stop.cleared")
    assert cleared
