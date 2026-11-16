"""Scope registry, target validation and authorization gates."""
import datetime as dt

import pytest

from backend import authentication, authorization
from backend.authorization import ScopeError
from backend.database import Authorization, User


def test_classify_target():
    c = authorization.classify_target
    assert c("10.0.0.0/24") == "cidr"
    assert c("10.0.0.5") == "ip"
    assert c("example.com") == "domain"
    assert c("https://app.example.com/path") == "url"
    assert c("can:vcan0") == "can"
    assert c("modbus://10.0.0.5:502") == "ics_endpoint"
    assert c("not a target at all") == "unknown"


def test_add_scope_detects_type(db):
    e = authorization.add_scope(db, "10.10.0.0/16", created_by="t")
    assert e.target_type == "cidr"
    e2 = authorization.add_scope(db, "corp.example.com", created_by="t")
    assert e2.target_type == "domain"


def test_add_scope_is_deduplicated(db):
    a = authorization.add_scope(db, "10.1.1.1", created_by="t")
    b = authorization.add_scope(db, "10.1.1.1", created_by="t")
    assert a.id == b.id


def test_cidr_scope_covers_member_ip(db):
    authorization.add_scope(db, "10.20.0.0/24", created_by="t")
    v = authorization.validate_targets(db, ["10.20.0.77"])
    assert v["all_in_scope"] is True
    v2 = authorization.validate_targets(db, ["10.21.0.77"])
    assert v2["all_in_scope"] is False


def test_domain_scope_covers_subdomain_and_url(db):
    authorization.add_scope(db, "example.com", created_by="t")
    for t in ("example.com", "app.example.com", "https://api.example.com/v1", "deep.a.example.com"):
        assert authorization.validate_targets(db, [t])["all_in_scope"] is True, t
    assert authorization.validate_targets(db, ["example.org"])["all_in_scope"] is False
    assert authorization.validate_targets(db, ["notexample.com"])["all_in_scope"] is False


def test_url_scope_is_prefix_match(db):
    authorization.add_scope(db, "https://app.example.com/api", created_by="t")
    assert authorization.validate_targets(db, ["https://app.example.com/api/v2"])["all_in_scope"] is True
    assert authorization.validate_targets(db, ["https://app.example.com/other"])["all_in_scope"] is False


def test_ics_and_can_scope_matching(db):
    authorization.add_scope(db, "modbus://127.0.0.1:5020", created_by="t")
    authorization.add_scope(db, "can:wdcan0", created_by="t")
    assert authorization.validate_targets(db, ["modbus://127.0.0.1:5020"])["all_in_scope"] is True
    assert authorization.validate_targets(db, ["can:wdcan0"])["all_in_scope"] is True


def _stage2(db):
    c = authentication.bootstrap(db)
    r = authentication.stage_one(db, c["username"], c["password"], c["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    authentication.stage_two(db, sess, c["pin"])
    return db.query(User).first(), sess


def test_authorization_requires_stage2(db):
    c = authentication.bootstrap(db)
    r = authentication.stage_one(db, c["username"], c["password"], c["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    authorization.add_scope(db, "example.com", created_by="t")
    u = db.query(User).first()
    with pytest.raises(ScopeError) as exc:
        authorization.create_authorization(db, u, sess, ["example.com"])
    assert exc.value.code == "STAGE2_REQUIRED"


def test_authorization_rejects_out_of_scope_target(db):
    u, sess = _stage2(db)
    authorization.add_scope(db, "example.com", created_by="t")
    with pytest.raises(ScopeError) as exc:
        authorization.create_authorization(db, u, sess, ["evil.example.org"])
    assert exc.value.code == "OUT_OF_SCOPE"


def test_authorization_records_scope_snapshot(db):
    u, sess = _stage2(db)
    authorization.add_scope(db, "example.com", created_by="t")
    a = authorization.create_authorization(db, u, sess, ["example.com"], note="unit test")
    assert a.confirmed is True
    assert a.scope_snapshot[0]["in_scope"] is True
    assert a.note == "unit test"


def test_assert_valid_enforces_expiry(db):
    u, sess = _stage2(db)
    authorization.add_scope(db, "example.com", created_by="t")
    a = authorization.create_authorization(db, u, sess, ["example.com"])
    assert authorization.assert_valid(db, a.id, ["example.com"]).id == a.id
    a.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
    db.commit()
    with pytest.raises(ScopeError) as exc:
        authorization.assert_valid(db, a.id, ["example.com"])
    assert exc.value.code == "AUTHZ_EXPIRED"


def test_assert_valid_enforces_target_subset(db):
    u, sess = _stage2(db)
    authorization.add_scope(db, "example.com", created_by="t")
    a = authorization.create_authorization(db, u, sess, ["example.com"])
    with pytest.raises(ScopeError) as exc:
        authorization.assert_valid(db, a.id, ["app.example.com"])
    assert exc.value.code == "AUTHZ_TARGET_MISMATCH"


def test_assert_valid_requires_an_id(db):
    with pytest.raises(ScopeError) as exc:
        authorization.assert_valid(db, None, ["example.com"])
    assert exc.value.code == "NO_AUTHZ"


def test_revoke_all_invalidates_authorizations(db):
    u, sess = _stage2(db)
    authorization.add_scope(db, "example.com", created_by="t")
    a = authorization.create_authorization(db, u, sess, ["example.com"])
    n = authorization.revoke_all(db, reason="test")
    assert n >= 1
    db.refresh(a)
    with pytest.raises(ScopeError) as exc:
        authorization.assert_valid(db, a.id, ["example.com"])
    assert exc.value.code == "AUTHZ_REVOKED"


def test_scope_ttl_is_capped(db, monkeypatch):
    u, sess = _stage2(db)
    authorization.add_scope(db, "example.com", created_by="t")
    monkeypatch.setattr(authorization.config, "AUTHZ_MAX_TTL_MINUTES", 10)
    a = authorization.create_authorization(db, u, sess, ["example.com"], ttl_minutes=9999)
    delta = a.expires_at.replace(tzinfo=None) - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    assert delta.total_seconds() <= 11 * 60
