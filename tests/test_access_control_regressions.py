"""Regression tests for the access-control defects found in the 2026-11-16 audit.

Each test reproduces the *pre-fix* behaviour as a negative control and asserts
the fixed contract, so a future refactor that re-opens the hole fails loudly:

1. SPA catch-all path traversal (unauthenticated read of any file).
2. Stage-1 session could rotate the stage-2 PIN and self-satisfy 2FA.
3. No stage-2 attempt ceiling / lockout on PIN guessing.
4. One global login-rate-limit row (single source could lock everyone out).
5. Any operator could spend another operator's authorization.
6. Integration execution (katana/nuclei/ksubdomain) needed only stage 1,
   no scope check and no emergency-stop check.
7. Concurrent audit appends could duplicate a sequence number.
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import text

from backend import audit, authentication


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _stage1(client, creds):
    r = client.post("/api/auth/stage1", json={
        "username": creds["username"], "password": creds["password"],
        "shortcut": creds["shortcut"]})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _login(client, creds):
    tok = _stage1(client, creds)
    r2 = client.post("/api/auth/stage2", json={"pin": creds["pin"]},
                     headers={"authorization": f"Bearer {tok}"})
    assert r2.status_code == 200, r2.text
    return tok


def _h(tok):
    return {"authorization": f"Bearer {tok}"}


# ---------------------------------------------------------------- 1. traversal --
def test_spa_catch_all_cannot_escape_frontend(client, operator):
    """`GET /../database/bootstrap_credentials.txt` used to return the file."""
    for path in ("/../database/bootstrap_credentials.txt",
                 "/..%2fdatabase%2fbootstrap_credentials.txt",
                 "/../../../../etc/passwd",
                 "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"):
        r = client.get(path)
        body = r.text
        assert "Operator password" not in body, (path, body[:200])
        assert "root:x:0:0" not in body, (path, body[:200])
    # the SPA still serves its own assets and falls back to index.html
    assert client.get("/").status_code == 200
    assert "<!doctype html" in client.get("/assets/app.js").text.lower() or \
        client.get("/assets/app.js").status_code == 200
    assert client.get("/some/spa/route").status_code == 200
    assert client.get("/api/definitely-not-a-route").status_code == 404


# ------------------------------------------------- 2. PIN rotation needs stage 2 --
def test_pin_rotation_requires_a_stage2_session(client, operator):
    tok = _stage1(client, operator)          # no PIN entered yet
    r = client.post("/api/auth/pin", json={"password": operator["password"],
                                           "new_pin": "424242"}, headers=_h(tok))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "STAGE2_REQUIRED"

    # with a completed stage 2 the rotation is allowed and the new PIN works
    tok2 = _login(client, operator)
    r2 = client.post("/api/auth/pin", json={"password": operator["password"],
                                            "new_pin": "424242"}, headers=_h(tok2))
    assert r2.status_code == 200, r2.text
    r3 = client.post("/api/auth/stage2", json={"pin": "424242"}, headers=_h(tok2))
    assert r3.status_code == 200


# ------------------------------------------------------- 3. PIN brute force bounded --
def test_stage2_pin_attempts_are_bounded_and_revoke_the_session(client, operator, monkeypatch):
    """A 6-8 digit PIN must not be iterable on one session.

    Pre-fix: 25 consecutive wrong PINs returned 401 each time and the correct
    PIN was still accepted afterwards - no throttle, no ceiling, no lockout.
    """
    # isolate the PIN ceiling from the account-lockout counter
    monkeypatch.setattr(authentication.config, "MAX_LOGIN_FAILURES", 500)
    tok = _stage1(client, operator)
    wrong = "00000000" if operator["pin"] != "00000000" else "11111111"
    codes = []
    for _ in range(authentication.STAGE2_MAX_ATTEMPTS + 2):
        r = client.post("/api/auth/stage2", json={"pin": wrong}, headers=_h(tok))
        codes.append(r.status_code)
        if r.status_code == 423:
            break
    assert codes[-1] == 423, codes
    assert len(codes) <= authentication.STAGE2_MAX_ATTEMPTS, codes
    # the session is revoked, so the *correct* PIN no longer elevates it
    r = client.post("/api/auth/stage2", json={"pin": operator["pin"]}, headers=_h(tok))
    assert r.status_code == 401, r.text


def test_stage2_lockout_counts_toward_the_account(db, operator, monkeypatch):
    monkeypatch.setattr(authentication.config, "MAX_LOGIN_FAILURES", 3)
    r = authentication.stage_one(db, operator["username"], operator["password"],
                                 operator["shortcut"])
    sess = authentication.session_from_token(db, r["token"])
    for _ in range(3):
        with pytest.raises(authentication.AuthError) as exc:
            authentication.stage_two(db, sess, "99999999")
        if exc.value.code == "LOCKED":
            break
    user = db.query(authentication.User).first()
    assert user.locked_until is not None


# --------------------------------------------------- 4. login throttle is per key --
def test_login_throttle_is_per_key_not_global(client, operator, monkeypatch):
    """Ten failures for one identity must not lock out a different operator."""
    monkeypatch.setattr(authentication.config, "RATE_LIMIT_ATTEMPTS", 3)
    # a distinct username so this test measures the shared-counter defect, not
    # the (intended) per-identity budget
    for _ in range(3):
        r = client.post("/api/auth/stage1", json={
            "username": "NOBODY-HERE", "password": "x" * 12, "shortcut": "WD-NOPE"})
        assert r.status_code == 401
    # the noisy identity is now throttled ...
    r = client.post("/api/auth/stage1", json={
        "username": "NOBODY-HERE", "password": "x" * 12, "shortcut": "WD-NOPE"})
    assert r.status_code == 429, r.text
    # ... but the real operator authenticates on its own budget
    tok = _stage1(client, operator)
    assert tok


# ------------------------------------------------- 5. authorization ownership --
def test_authorization_cannot_be_spent_by_another_operator(client, operator, db):
    tok = _login(client, operator)
    client.post("/api/scope", json={"target": "example.com"}, headers=_h(tok))
    az = client.post("/api/authorizations", json={"targets": ["example.com"],
                                                   "note": "owned by first operator"},
                     headers=_h(tok))
    assert az.status_code == 200, az.text
    authz_id = az.json()["id"]

    # a second operator, fully stage-2, with its own assessment on the same target
    r = client.post("/api/auth/operators", json={"username": "WD-OTHER",
                                                "password": "Other-Operator-2026",
                                                "pin": "31415926", "role": "operator"},
                    headers=_h(tok))
    assert r.status_code == 200, r.text
    tok2 = _login(client, {"username": "WD-OTHER", "password": "Other-Operator-2026",
                          "pin": "31415926", "shortcut": operator["shortcut"]})
    # the new operator must not inherit the other operator's password rotation gate
    db.execute(text("UPDATE users SET must_change_password=0 WHERE username='WD-OTHER'"))
    db.commit()

    a = client.post("/api/assessments", json={"template": "physical_pentest",
                                              "targets": ["example.com"]}, headers=_h(tok2))
    assert a.status_code == 200, a.text
    aid = a.json()["id"]
    run = client.post(f"/api/assessments/{aid}/run", json={"authz_id": authz_id,
                                                           "confirm": True}, headers=_h(tok2))
    assert run.status_code == 403, run.text
    assert run.json()["detail"]["code"] == "AUTHZ_FOREIGN"

    # the owner can still use it
    a2 = client.post("/api/assessments", json={"template": "physical_pentest",
                                               "targets": ["example.com"]}, headers=_h(tok))
    run2 = client.post(f"/api/assessments/{a2.json()['id']}/run",
                       json={"authz_id": authz_id, "confirm": True}, headers=_h(tok))
    assert run2.status_code == 200, run2.text


# ------------------------------------- 6. integration execution is a real test --
def test_integration_execution_requires_stage2_and_scope(client, operator):
    tok1 = _stage1(client, operator)
    r = client.post("/api/integrations/nuclei/sqli", json={"url": "http://127.0.0.1:1/"},
                    headers=_h(tok1))
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["code"] == "STAGE2_REQUIRED"

    tok2 = _login(client, operator)
    out = client.post("/api/integrations/nuclei/sqli", json={"url": "http://127.0.0.1:1/"},
                      headers=_h(tok2))
    assert out.status_code == 403, out.text
    assert out.json()["detail"]["code"] == "OUT_OF_SCOPE"

    client.post("/api/scope", json={"target": "http://127.0.0.1:1"}, headers=_h(tok2))
    ok = client.post("/api/scope/validate", json={"targets": ["http://127.0.0.1:1"]},
                     headers=_h(tok2))
    assert ok.json()["all_in_scope"] is True


def test_integration_execution_honours_the_emergency_stop(client, operator):
    tok = _login(client, operator)
    client.post("/api/scope", json={"target": "http://127.0.0.1:1"}, headers=_h(tok))
    client.post("/api/emergency-stop", json={"reason": "unit"}, headers=_h(tok))
    tok2 = _login(client, operator)  # sessions are revoked by the stop; re-auth
    r = client.post("/api/integrations/katana/crawl", json={"url": "http://127.0.0.1:1"},
                    headers=_h(tok2))
    assert r.status_code == 423, r.text
    assert r.json()["detail"]["code"] == "EMERGENCY_STOP"
    client.post("/api/emergency-stop/clear", headers=_h(tok2))


# --------------------------------------------------- 7. audit append concurrency --
def test_concurrent_audit_appends_keep_the_chain_valid(client, operator, db):
    audit.record("test.seed", actor="a", db=db)
    errors = []

    def worker(n: int):
        try:
            audit.record("test.concurrent", actor="t", target=str(n), detail={"n": n})
        except Exception as exc:  # pragma: no cover - reported through the assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    v = audit.verify_chain(db)
    assert v["valid"] is True, v
    dups = db.execute(text(
        "SELECT seq, COUNT(*) c FROM audit_events GROUP BY seq HAVING c > 1")).fetchall()
    assert dups == [], dups



# -------------------------------------------------- assessment read isolation --
def test_operator_cannot_read_another_operators_assessment(client, operator, db):
    owner_token = _login(client, operator)
    client.post("/api/scope", json={"target": "example.com"}, headers=_h(owner_token))
    created = client.post(
        "/api/assessments",
        json={"template": "physical_pentest", "targets": ["example.com"]},
        headers=_h(owner_token),
    )
    assert created.status_code == 200, created.text
    assessment_id = created.json()["id"]

    made = client.post(
        "/api/auth/operators",
        json={"username": "WD-PRIVATE-READER", "password": "Private-Reader-2026",
              "pin": "31415926", "role": "operator"},
        headers=_h(owner_token),
    )
    assert made.status_code == 200, made.text
    db.execute(text(
        "UPDATE users SET must_change_password=0 WHERE username='WD-PRIVATE-READER'"
    ))
    db.commit()
    reader_token = _login(client, {
        "username": "WD-PRIVATE-READER", "password": "Private-Reader-2026",
        "pin": "31415926", "shortcut": operator["shortcut"],
    })
    headers = _h(reader_token)

    listed = client.get("/api/assessments", headers=headers).json()["assessments"]
    assert all(row["id"] != assessment_id for row in listed)
    assert client.get(f"/api/assessments/{assessment_id}", headers=headers).status_code == 404
    assert client.get(
        f"/api/assessments/{assessment_id}/findings", headers=headers
    ).status_code == 404
    assert client.get(
        f"/api/assessments/{assessment_id}/report?fmt=md", headers=headers
    ).status_code == 404
    assert client.post(
        f"/api/assessments/{assessment_id}/report/save?fmt=md", headers=headers
    ).status_code == 404
    artax = client.post(
        "/api/artax/ask",
        json={"question": "Summarize this assessment", "assessment_id": assessment_id},
        headers=headers,
    )
    assert artax.status_code == 404, artax.text
