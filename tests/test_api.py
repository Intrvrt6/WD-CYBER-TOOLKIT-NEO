"""API-level integration tests through FastAPI TestClient (real HTTP contract)."""
import json

import pytest


def _login(client, creds):
    r = client.post("/api/auth/stage1", json={
        "username": creds["username"], "password": creds["password"], "shortcut": creds["shortcut"]})
    assert r.status_code == 200, r.text
    tok = r.json()["token"]
    r2 = client.post("/api/auth/stage2", json={"pin": creds["pin"]},
                     headers={"authorization": f"Bearer {tok}"})
    assert r2.status_code == 200, r2.text
    return tok


def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "engines" in body


def test_capabilities_is_public_and_honest(client):
    r = client.get("/api/capabilities")
    assert r.status_code == 200
    body = r.json()
    assert "cli_tools" in body and "python_modules" in body
    assert all("present" in v for v in body["python_modules"].values())


def test_protected_endpoint_requires_token(client):
    assert client.get("/api/scope").status_code == 401
    assert client.get("/api/scope", headers={"authorization": "Bearer nope"}).status_code == 401


def test_stage1_rejects_bad_shortcut(client, operator):
    r = client.post("/api/auth/stage1", json={
        "username": operator["username"], "password": operator["password"], "shortcut": "WD-INCORRECT"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "INVALID_CREDENTIALS"


def test_stage1_stage2_flow_and_me(client, operator):
    tok = _login(client, operator)
    me = client.get("/api/auth/me", headers={"authorization": f"Bearer {tok}"}).json()
    assert me["stage"] == 2
    assert me["user"]["username"] == operator["username"]


def test_stage2_requires_correct_pin(client, operator):
    r = client.post("/api/auth/stage1", json={
        "username": operator["username"], "password": operator["password"], "shortcut": operator["shortcut"]})
    tok = r.json()["token"]
    bad = "00000000" if operator["pin"] != "00000000" else "11111111"
    r2 = client.post("/api/auth/stage2", json={"pin": bad}, headers={"authorization": f"Bearer {tok}"})
    assert r2.status_code == 401
    assert r2.json()["detail"]["code"] == "INVALID_PIN"


def test_stage2_endpoint_is_gated(client, operator):
    r = client.post("/api/auth/stage1", json={
        "username": operator["username"], "password": operator["password"], "shortcut": operator["shortcut"]})
    tok = r.json()["token"]
    h = {"authorization": f"Bearer {tok}"}
    assert client.post("/api/authorizations", json={"targets": ["example.com"]}, headers=h).status_code == 403
    assert client.post("/api/assessments", json={"template": "network_pentest", "targets": ["example.com"]},
                       headers=h).status_code == 403


def test_scope_crud_and_validation(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    r = client.post("/api/scope", json={"target": "example.com", "description": "unit"}, headers=h)
    assert r.status_code == 200 and r.json()["target_type"] == "domain"
    lst = client.get("/api/scope", headers=h).json()["scope"]
    assert any(s["target"] == "example.com" for s in lst)
    v = client.post("/api/scope/validate", json={"targets": ["app.example.com"]}, headers=h).json()
    assert v["all_in_scope"] is True
    v2 = client.post("/api/scope/validate", json={"targets": ["other.test"]}, headers=h).json()
    assert v2["all_in_scope"] is False


def test_templates_endpoint_lists_all_ten(client, operator):
    tok = _login(client, operator)
    tpls = client.get("/api/templates", headers={"authorization": f"Bearer {tok}"}).json()["templates"]
    ids = {t["id"] for t in tpls}
    assert {"network_pentest", "scada_pentest", "can_pentest", "ioc_pentest",
            "webapp_pentest", "mobile_pentest", "physical_pentest",
            "hardware_pentest", "social_pentest", "mitm_pentest"} <= ids
    for t in tpls:
        assert t["checklist"], t["id"]


def test_authorization_and_assessment_creation(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    client.post("/api/scope", json={"target": "example.com"}, headers=h)
    bad = client.post("/api/authorizations", json={"targets": ["outside.test"]}, headers=h)
    assert bad.status_code == 403 and bad.json()["detail"]["code"] == "OUT_OF_SCOPE"
    ok = client.post("/api/authorizations", json={"targets": ["example.com"], "ttl_minutes": 15}, headers=h)
    assert ok.status_code == 200
    authz = ok.json()["id"]
    a = client.post("/api/assessments", json={"template": "network_pentest", "targets": ["example.com"],
                                             "mode": "live", "intensity": "light"}, headers=h)
    assert a.status_code == 200
    body = a.json()
    assert body["preflight"]["ok"] is True
    assert body["status"] == "created"
    # running without an authorization must fail
    nf = client.post(f"/api/assessments/{body['id']}/run", json={"authz_id": "missing", "confirm": True}, headers=h)
    assert nf.status_code == 403
    run = client.post(f"/api/assessments/{body['id']}/run", json={"authz_id": authz, "confirm": True}, headers=h)
    assert run.status_code == 200 and run.json()["job_id"]
    j = client.get(f"/api/jobs/{run.json()['job_id']}", headers=h).json()
    assert j["status"] in ("queued", "running", "completed")


def test_report_generation_all_formats(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    client.post("/api/scope", json={"target": "example.com"}, headers=h)
    a = client.post("/api/assessments", json={"template": "network_pentest", "targets": ["example.com"],
                                             "mode": "live", "intensity": "light"}, headers=h).json()
    md = client.get(f"/api/assessments/{a['id']}/report?fmt=md&lang=en", headers=h)
    assert md.status_code == 200 and "Executive Summary" in md.text
    idn = client.get(f"/api/assessments/{a['id']}/report?fmt=md&lang=id", headers=h)
    assert "Ringkasan Eksekutif" in idn.text
    pdf = client.get(f"/api/assessments/{a['id']}/report?fmt=pdf&lang=en", headers=h)
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    html = client.get(f"/api/assessments/{a['id']}/report?fmt=html&lang=en", headers=h)
    assert html.status_code == 200 and "<html" in html.text.lower()


def test_audit_endpoints_and_chain(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    v = client.get("/api/audit/verify", headers=h).json()
    assert v["valid"] is True
    ev = client.get("/api/audit?limit=20", headers=h).json()
    assert ev["count"] >= 1
    j = client.get("/api/audit/export?fmt=json", headers=h)
    assert json.loads(j.text)["count"] >= 1
    c = client.get("/api/audit/export?fmt=csv", headers=h)
    assert c.text.startswith("seq,ts,actor")


def test_emergency_stop_blocks_then_requires_stage2_to_clear(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    client.post("/api/scope", json={"target": "example.com"}, headers=h)
    r = client.post("/api/emergency-stop", json={"reason": "api test"}, headers=h)
    assert r.status_code == 200 and r.json()["active"] is True

    # Activation revokes every session server-side, so the old token is dead.
    assert client.get("/api/auth/me", headers=h).status_code == 401

    # After a fresh stage-1 + stage-2 the stop gate (not auth) blocks execution.
    tok2 = _login(client, operator)
    h2 = {"authorization": f"Bearer {tok2}"}
    blocked = client.post("/api/authorizations", json={"targets": ["example.com"]}, headers=h2)
    assert blocked.status_code == 423
    assert blocked.json()["detail"]["code"] == "EMERGENCY_STOP"

    cleared = client.post("/api/emergency-stop/clear", headers=h2)
    assert cleared.status_code == 200 and cleared.json()["active"] is False
    ok = client.post("/api/authorizations", json={"targets": ["example.com"]}, headers=h2)
    assert ok.status_code == 200


def test_logout_revokes_session(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401


def test_modules_endpoint_reports_engine_status(client, operator):
    tok = _login(client, operator)
    body = client.get("/api/modules", headers={"authorization": f"Bearer {tok}"}).json()
    assert "modules" in body and "registered" in body
    for m in body["modules"]:
        assert m["checks"]
