"""Artax AI: local analyst, context grounding, endpoint path, API surface."""
import json

import pytest

from backend.artax.client import ArtaxClient, ArtaxError, local_analysis
from backend.artax.prompts import build_assessment_context, build_platform_context


ASSESSMENT = {
    "id": "a1", "name": "net demo", "template": "network_pentest", "module": "network",
    "mode": "live", "intensity": "light", "status": "completed", "risk_score": 5.5,
    "targets": ["testssl.sh"], "operator": "op",
    "summary": {"checks_expected": ["NET-01", "NET-02", "NET-03"],
                "checks_reported": ["NET-01", "NET-02"],
                "by_severity": {"medium": 1, "info": 1},
                "by_source": {"live": 2}, "unavailable": 1},
}
FINDINGS = [
    {"check_id": "NET-02b", "severity": "medium", "evidence_source": "live",
     "title": "Sensitive ports", "asset": "testssl.sh", "cvss_score": 5.3,
     "cwe": ["CWE-1327"], "description": "ssh reachable",
     "remediation": "Restrict to mgmt VLAN"},
    {"check_id": "NET-01", "severity": "info", "evidence_source": "live",
     "title": "Discovery"},
]


# ------------------------------------------------------------- context ----
def test_context_contains_evidence_only():
    ctx = build_assessment_context(ASSESSMENT, FINDINGS)
    assert "NET-02b" in ctx and "medium" in ctx and "src=live" in ctx
    assert "Restrict to mgmt VLAN" in ctx
    assert "checks_expected" in ctx and "targets: testssl.sh" in ctx


def test_context_reports_missing_checks_explicitly():
    ctx = build_assessment_context(ASSESSMENT, FINDINGS)
    assert "CHECKS THAT DID NOT REPORT: NET-03" in ctx


def test_context_orders_by_severity():
    ctx = build_assessment_context(ASSESSMENT, FINDINGS)
    # Compare inside the FINDINGS section only: check ids also appear in the
    # checks_expected line, so a whole-document index would be meaningless.
    findings_block = ctx.split("=== FINDINGS (severity ordered) ===", 1)[1]
    assert findings_block.index("NET-02b") < findings_block.index("[NET-01]")


def test_context_truncates_and_says_so():
    many = [dict(FINDINGS[0], check_id=f"X-{i:02d}") for i in range(60)]
    ctx = build_assessment_context(ASSESSMENT, many, max_findings=5)
    assert "more findings omitted" in ctx


def test_platform_context_lists_engines_and_missing_tools():
    ctx = build_platform_context(
        {"instance": "WD", "version": "1.1.0",
         "engines": {"registered": ["network", "webapp"], "failed": {"scada_ics": "x"}},
         "emergency_stop": {"active": False}},
        {"modules": [{"module": "network", "checks": [1, 2]}]},
        {"cli_tools": {"nmap": {"present": True}, "zeek": {"present": False}}})
    assert "network" in ctx and "scada_ics" in ctx and "zeek" in ctx


# --------------------------------------------------------- local analyst ----
def test_local_analysis_summarises_and_prioritises():
    ctx = build_assessment_context(ASSESSMENT, FINDINGS)
    out = local_analysis("what is the priority?", ctx)
    assert "Assessment summary" in out
    assert "NET-02b" in out
    assert "network_pentest" in out


def test_local_analysis_flags_unavailable_as_gap_not_pass():
    ctx = build_assessment_context(ASSESSMENT, FINDINGS)
    out = local_analysis("coverage?", ctx)
    assert "unavailable" in out
    assert "not evidence of absence" in out


def test_local_analysis_lists_coverage_gaps():
    ctx = build_assessment_context(ASSESSMENT, FINDINGS)
    out = local_analysis("what did not run?", ctx)
    assert "NET-03" in out and "NOT TESTED" in out


def test_local_analysis_returns_remediation_when_asked():
    ctx = build_assessment_context(ASSESSMENT, FINDINGS)
    out = local_analysis("apa prioritas perbaikan?", ctx)
    assert "Restrict to mgmt VLAN" in out


def test_local_analysis_refuses_to_invent_without_context():
    out = local_analysis("tell me everything", "")
    assert "No evidence context" in out


def test_local_analysis_notes_lab_source():
    a = dict(ASSESSMENT)
    a["summary"] = dict(ASSESSMENT["summary"], by_source={"'lab'": 10})
    ctx = build_assessment_context(a, [])
    out = local_analysis("summary", ctx)
    assert "simulator" in out


# ---------------------------------------------------------------- client ----
def test_client_defaults_to_local_mode(monkeypatch):
    monkeypatch.setattr("backend.config.ARTAX_BASE_URL", "")
    c = ArtaxClient()
    assert c.mode == "local"
    r = c.ask("q", build_assessment_context(ASSESSMENT, FINDINGS))
    assert r["parser"] == "local-rules"
    assert r["model"] == "deterministic-evidence-analyst"


def test_client_rejects_empty_question():
    with pytest.raises(ArtaxError) as exc:
        ArtaxClient().ask("   ", "")
    assert exc.value.code == "EMPTY_QUESTION"


def test_client_disabled_mode(monkeypatch):
    monkeypatch.setattr("backend.config.ARTAX_ENABLED", False)
    with pytest.raises(ArtaxError) as exc:
        ArtaxClient().ask("q", "")
    assert exc.value.code == "DISABLED"


def test_client_endpoint_mode_unreachable_raises(monkeypatch):
    c = ArtaxClient(base_url="http://127.0.0.1:9/v1", timeout=2)
    assert c.mode == "endpoint"
    with pytest.raises(ArtaxError) as exc:
        c.ask("q", "")
    assert exc.value.code == "ENDPOINT_UNREACHABLE"


# ------------------------------------------------------------- api layer ----
def _login(client, creds):
    r = client.post("/api/auth/stage1", json={"username": creds["username"],
                                              "password": creds["password"],
                                              "shortcut": creds["shortcut"]})
    tok = r.json()["token"]
    client.post("/api/auth/stage2", json={"pin": creds["pin"]},
                headers={"authorization": f"Bearer {tok}"})
    return tok


def test_api_status_requires_auth(client):
    assert client.get("/api/artax/status").status_code == 401


def test_api_status_reports_mode(client, operator):
    tok = _login(client, operator)
    r = client.get("/api/artax/status", headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] in ("local", "endpoint", "disabled")
    assert "endpoint_configured" in body


def test_api_ask_grounds_in_platform_when_no_assessment(client, operator):
    tok = _login(client, operator)
    r = client.post("/api/artax/ask", json={"question": "which modules exist?", "scope": "platform"},
                    headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert body["scope"] == "platform"
    assert "Engines" in body["answer"] or "engines" in body["answer"]


def test_api_ask_on_assessment_uses_its_findings(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    client.post("/api/scope", json={"target": "example.com"}, headers=h)
    a = client.post("/api/assessments", json={"template": "network_pentest",
                                             "targets": ["example.com"],
                                             "mode": "live", "intensity": "light"},
                    headers=h).json()
    r = client.post("/api/artax/ask", json={"question": "summarise",
                                            "assessment_id": a["id"]}, headers=h)
    assert r.status_code == 200
    assert r.json()["scope"] == "assessment"


def test_api_ask_unknown_assessment_404(client, operator):
    tok = _login(client, operator)
    r = client.post("/api/artax/ask", json={"question": "q", "assessment_id": "nope"},
                    headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 404


def test_api_presets_listed(client, operator):
    tok = _login(client, operator)
    r = client.get("/api/artax/presets", headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    ids = {p["id"] for p in r.json()["presets"]}
    assert {"executive_summary", "remediation_plan", "coverage_review"} <= ids


def test_api_unknown_preset_404(client, operator):
    tok = _login(client, operator)
    r = client.post("/api/artax/preset/nope", headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 404


def test_api_stream_returns_text(client, operator):
    tok = _login(client, operator)
    r = client.post("/api/artax/stream", json={"question": "hi", "scope": "platform"},
                    headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.text
    assert r.headers.get("x-artax-mode") in ("local", "endpoint")


def test_api_ask_is_audited(client, operator):
    tok = _login(client, operator)
    h = {"authorization": f"Bearer {tok}"}
    client.post("/api/artax/ask", json={"question": "audited?", "scope": "platform"}, headers=h)
    events = client.get("/api/audit?action=artax.ask&limit=10", headers=h).json()["events"]
    assert events and events[0]["action"] == "artax.ask"
