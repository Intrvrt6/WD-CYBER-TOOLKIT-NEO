"""Two-stage authentication, lockout, session lifecycle."""
import datetime as dt

import pytest

from backend import authentication
from backend.authentication import AuthError
from backend.database import Shortcut, User


@pytest.fixture()
def creds(db):
    c = authentication.bootstrap(db)
    assert c is not None, "bootstrap should create the first operator"
    return c


def test_bootstrap_is_idempotent(db, creds):
    assert authentication.bootstrap(db) is None
    assert db.query(User).count() == 1


def test_bootstrap_credentials_file_is_private_and_has_line_breaks(db, creds):
    import os
    import stat
    from backend import config

    path = config.DATA_DIR / "bootstrap_credentials.txt"
    assert path.exists()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    content = path.read_text(encoding="utf-8")
    assert "\\n" not in content
    assert "Operator username :" in content
    assert "Operator password :" in content

def test_bootstrap_persists_only_hashes(db, creds):
    u = db.query(User).first()
    assert u.password_hash.startswith("$argon2id$")
    assert creds["password"] not in u.password_hash
    assert u.pin_hash.startswith("$argon2id$")
    sc = db.query(Shortcut).first()
    assert sc.code_hash.startswith("$argon2id$")
    assert creds["shortcut"] not in sc.code_hash


def test_stage_one_requires_both_password_and_shortcut(db, creds):
    ok = authentication.stage_one(db, creds["username"], creds["password"], creds["shortcut"])
    assert ok["stage"] == 1 and ok["token"]
    with pytest.raises(AuthError):
        authentication.stage_one(db, creds["username"], creds["password"], "WD-WRONG")
    db.rollback()
    with pytest.raises(AuthError):
        authentication.stage_one(db, creds["username"], "wrongpass", creds["shortcut"])

dp = None


def test_stage_two_requires_correct_pin(db, creds):
    r = authentication.stage_one(db, creds["username"], creds["password"], creds["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    assert sess.stage == 1
    with pytest.raises(AuthError):
        authentication.stage_two(db, sess, "00000000" if creds["pin"] != "00000000" else "11111111")
    db.rollback()
    out = authentication.stage_two(db, sess, creds["pin"])
    assert out["stage"] == 2
    assert authentication.session_from_token(db, r["token"]).stage == 2


def test_session_token_is_not_stored_in_clear(db, creds):
    from backend.database import Session
    r = authentication.stage_one(db, creds["username"], creds["password"], creds["shortcut"])
    row = db.query(Session).first()
    assert row.token_hash != r["token"]
    assert len(row.token_hash) == 64


def test_revoked_session_is_rejected(db, creds):
    r = authentication.stage_one(db, creds["username"], creds["password"], creds["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    sess.revoked = True
    db.commit()
    assert authentication.session_from_token(db, r["token"]) is None


def test_expired_session_is_rejected(db, creds):
    r = authentication.stage_one(db, creds["username"], creds["password"], creds["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    sess.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=5)
    db.commit()
    assert authentication.session_from_token(db, r["token"]) is None


def test_account_lockout_after_failures(db, creds, monkeypatch):
    monkeypatch.setattr(authentication.config, "MAX_LOGIN_FAILURES", 3)
    for _ in range(3):
        with pytest.raises(AuthError):
            authentication.stage_one(db, creds["username"], "bad", "WD-BAD")
    u = db.query(User).first()
    assert u.locked_until is not None
    with pytest.raises(AuthError) as exc:
        authentication.stage_one(db, creds["username"], creds["password"], creds["shortcut"])
    assert exc.value.code == "LOCKED"


def test_successful_login_clears_failure_count(db, creds):
    with pytest.raises(AuthError):
        authentication.stage_one(db, creds["username"], "bad", creds["shortcut"])
    authentication.stage_one(db, creds["username"], creds["password"], creds["shortcut"])
    assert db.query(User).first().failed_count == 0


def test_change_password_enforces_policy(db, creds):
    u = db.query(User).first()
    with pytest.raises(AuthError):
        authentication.change_password(db, u, creds["password"], "weak")
    authentication.change_password(db, u, creds["password"], "Brand-New-Pass-42")
    assert not u.must_change_password


def test_change_pin_requires_password(db, creds):
    u = db.query(User).first()
    with pytest.raises(AuthError):
        authentication.change_pin(db, u, "wrong", "123456")
    with pytest.raises(AuthError):
        authentication.change_pin(db, u, creds["password"], "12")
    authentication.change_pin(db, u, creds["password"], "87654321")
