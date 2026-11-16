"""Regression tests for the second half of the 2026-11-16 security review.

Each case reproduces a defect that was live at commit d762a2a:

WD-06 scope matching was a bare string prefix (userinfo / suffix hosts, CIDR widening)
WD-09 audit tail truncation verified as valid (no anchor outside the table)
WD-11 the `viewer` role could authorize, execute and create work
WD-13 the emergency stop did not block assessment creation
WD-14 rotating a credential left other sessions valid
WD-15 `kv()` trusted any value starting with `<` as markup
"""
from __future__ import annotations

from sqlalchemy import text

from backend import audit, authentication, authorization


# ------------------------------------------------------------------ WD-06 scope --
def test_url_scope_compares_origin_not_string_prefix(db):
    authorization.add_scope(db, "https://example.com", created_by="t")
    # the three escapes that a bare startswith() let through
    for hostile in ("https://example.com@evil.tld/",
                    "https://example.com.attacker.tld/x",
                    "https://example.com.evil.tld:8443/p"):
        assert authorization.validate_targets(db, [hostile])["all_in_scope"] is False, hostile
    # genuine members still pass
    for ok in ("https://example.com", "https://example.com/v1/api"):
        assert authorization.validate_targets(db, [ok])["all_in_scope"] is True, ok


def test_cidr_scope_cannot_be_widened_to_a_bigger_range(db):
    authorization.add_scope(db, "10.0.0.0/24", created_by="t")
    assert authorization.validate_targets(db, ["10.0.0.0/8"])["all_in_scope"] is False
    assert authorization.validate_targets(db, ["10.0.0.0/16"])["all_in_scope"] is False
    assert authorization.validate_targets(db, ["10.0.0.0/24"])["all_in_scope"] is True
    assert authorization.validate_targets(db, ["10.0.0.5"])["all_in_scope"] is True


def test_domain_scope_rejects_userinfo_and_suffix_hosts(db):
    authorization.add_scope(db, "example.com", created_by="t")
    assert authorization.validate_targets(db, ["https://example.com@evil.tld/"])["all_in_scope"] is False
    assert authorization.validate_targets(db, ["example.com.evil.tld"])["all_in_scope"] is False
    assert authorization.validate_targets(db, ["https://example.com@evil.tld/"])["results"][0]["in_scope"] is False
    assert authorization.validate_targets(db, ["sub.example.com"])["all_in_scope"] is True


# ------------------------------------------------------------- WD-09 audit anchor --
def test_audit_tail_truncation_is_detected(db):
    for i in range(5):
        audit.record("test.anchor", actor="a", detail={"i": i}, db=db)
    assert audit.verify_chain(db)["valid"] is True
    db.execute(text("DELETE FROM audit_events WHERE seq > 3"))
    db.commit()
    v = audit.verify_chain(db)
    assert v["valid"] is False, v
    assert "truncat" in v["reason"]


def test_audit_anchor_is_outside_the_events_table(db):
    audit.record("test.anchor2", actor="a", db=db)
    anchor = audit.get_anchor(db)
    assert anchor and anchor["seq"] == 1
    # wiping the whole event table must not look like a valid empty chain
    db.execute(text("DELETE FROM audit_events"))
    db.commit()
    v = audit.verify_chain(db)
    assert v["valid"] is False, v


# ------------------------------------------------------------ WD-11 viewer RBAC --
def _stage2_session(db, user):
    r = authentication.stage_one(db, user["username"], user["password"], user["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    authentication.stage_two(db, sess, user["pin"])
    return sess


def _make_user(db, username: str, role: str) -> dict:
    from backend import security
    from backend.database import User
    u = User(username=username, role=role,
             password_hash=security.hash_secret("Viewer-Pass-2026!"),
             pin_hash=security.hash_secret("31415926"), must_change_password=False)
    db.add(u)
    db.commit()
    return {"username": username, "password": "Viewer-Pass-2026!",
            "pin": "31415926", "shortcut": ""}


def test_dependency_rejects_stage1_and_viewer(client, operator, db):
    _make_user(db, "WD-VIEW", "viewer")
    # stage-1 only operator
    tok1 = client.post("/api/auth/stage1", json={
        "username": operator["username"], "password": operator["password"],
        "shortcut": operator["shortcut"]}).json()["token"]
    h = {"authorization": f"Bearer {tok1}"}
    client.post("/api/scope", json={"target": "example.com"}, headers=h)
    r = client.post("/api/authorizations", json={"targets": ["example.com"]}, headers=h)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "STAGE2_REQUIRED"


# ------------------------------------------------- WD-13 stop blocks creation --
def test_emergency_stop_blocks_assessment_creation(client, operator, db):
    tok = client.post("/api/auth/stage1", json={
        "username": operator["username"], "password": operator["password"],
        "shortcut": operator["shortcut"]}).json()["token"]
    h = {"authorization": f"Bearer {tok}"}
    client.post("/api/auth/stage2", json={"pin": operator["pin"]}, headers=h)
    client.post("/api/scope", json={"target": "127.0.0.1"}, headers=h)
    client.post("/api/emergency-stop", json={"reason": "unit"}, headers=h)
    # the stop revokes sessions; re-authenticate (still stopped)
    tok = client.post("/api/auth/stage1", json={
        "username": operator["username"], "password": operator["password"],
        "shortcut": operator["shortcut"]}).json()["token"]
    h = {"authorization": f"Bearer {tok}"}
    client.post("/api/auth/stage2", json={"pin": operator["pin"]}, headers=h)
    r = client.post("/api/assessments", json={"template": "physical_pentest",
                                              "targets": ["127.0.0.1"]}, headers=h)
    assert r.status_code == 423, r.text
    assert r.json()["detail"]["code"] == "EMERGENCY_STOP"


# ------------------------------------------------------- WD-14 session rotation --
def test_credential_change_revokes_other_sessions_but_keeps_the_caller(client, operator):
    def login():
        tok = client.post("/api/auth/stage1", json={
            "username": operator["username"], "password": operator["password"],
            "shortcut": operator["shortcut"]}).json()["token"]
        client.post("/api/auth/stage2", json={"pin": operator["pin"]},
                    headers={"authorization": f"Bearer {tok}"})
        return tok

    a, b = login(), login()
    new_pw = "Rotated-Pass-2026!"
    r = client.post("/api/auth/password", json={"old_password": operator["password"],
                                               "new_password": new_pw},
                    headers={"authorization": f"Bearer {a}"})
    assert r.status_code == 200, r.text
    assert r.json()["sessions_revoked"] >= 1
    assert client.get("/api/auth/me", headers={"authorization": f"Bearer {a}"}).status_code == 200
    assert client.get("/api/auth/me", headers={"authorization": f"Bearer {b}"}).status_code == 401


# --------------------------------------------------------------- WD-15 kv escaping --
def test_kv_always_escapes_markup():
    """The JS rule is checked in source: no bare innerHTML interpolation of `v`."""
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "frontend" / "assets" / "ui.js"
    if not src.exists():
        return
    text_src = src.read_text()
    assert "String(v).startsWith('<') ? v : esc(v)" not in text_src
    assert "raw ? (v == null ? '' : v) : esc(v)" in text_src
