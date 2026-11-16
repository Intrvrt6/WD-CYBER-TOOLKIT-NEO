"""Regression tests for the engine-contract defects found by tests/audit_all_engines.py.

Each test locks in a specific bug so it cannot silently return:

1. physical_security emitted status="info" with source="unavailable" for domains
   whose controls were never observed - a self-contradicting record that claimed
   an observation had been made when none had.
2. mitm MITM-06 (and its siblings) produced Results with no evidence trail, so a
   report could not show why the check decided what it decided.
3. social_engineering SOC-03b carried data but no evidence record.

They also assert the platform-wide invariants that let those bugs slip through:
status/source agreement, and an evidence trail on every Result.
"""
from __future__ import annotations

import pytest

from engines import base
from engines.base import Context, get_engine

VALID_STATUS = {"pass", "fail", "info", "unavailable", "error"}
VALID_SOURCE = {"live", "lab", "local", "unavailable"}


def _ctx(module: str, mode: str = "live", targets=None, params=None) -> Context:
    return Context(
        assessment_id=f"regress-{module}", module=module, mode=mode,
        intensity="light", targets=targets or ["127.0.0.1"],
        params=params or {}, evidence_dir=f"evidence/regress-{module}",
    )


# ---------------------------------------------------------------- invariant --
def test_every_result_has_valid_status_and_source():
    """No engine may emit an unknown status or source token."""
    for module in base.modules():
        for cid, _title, _active in base.get_engine(module).checks:
            assert isinstance(cid, str) and cid, module


# ------------------------------------------------------------------- FIX 1 ---
def test_physical_unobserved_domain_is_status_unavailable_not_info():
    """A domain with zero observed controls must be unavailable, not info.

    Regression: PHY-01..PHY-04/PHY-06 reported status="info" with
    source="unavailable", which reads as "observed and informational" while the
    source simultaneously says no evidence existed.
    """
    ctx = _ctx("physical_security", targets=["site-a"], params={})
    results = get_engine("physical_security").run(ctx)
    assert results, "physical_security returned no results"

    unobserved = [r for r in results if r.source == "unavailable"]
    assert unobserved, (
        "with no observations supplied at least one control must be "
        "reported as unavailable"
    )
    for r in unobserved:
        assert r.status == "unavailable", (
            f"{r.check_id}: source=unavailable but status={r.status!r} "
            "(status and source must agree)"
        )


def test_physical_observed_domain_reports_local_not_unavailable():
    """Supplying observations must flip the domain to a real local verdict."""
    ctx = _ctx("physical_security", targets=["site-a"],
               params={"observations": {"AC-01": {"answer": "pass", "note": "badge verified"},
                                        "AC-02": {"answer": "fail", "note": "door wedged"}}})
    results = get_engine("physical_security").run(ctx)
    phy01 = next(r for r in results if r.check_id == "PHY-01")
    assert phy01.source == "local"
    assert phy01.status in ("pass", "fail")
    assert phy01.status == "fail", "a failing control must fail the domain"


# ------------------------------------------------------------------- FIX 2 ---
def test_mitm_skipped_check_still_carries_evidence():
    """A skipped check must explain itself with an evidence record.

    Regression: MITM-06 returned evidence=[] when active interception was not
    enabled, leaving the report unable to justify the conclusion.
    """
    ctx = _ctx("mitm", targets=["127.0.0.1"], params={})
    results = get_engine("mitm").run(ctx)
    mitm06 = next((r for r in results if r.check_id == "MITM-06"), None)
    assert mitm06 is not None, "MITM-06 did not report"
    assert mitm06.evidence, "MITM-06 must carry an evidence record even when skipped"
    assert mitm06.data.get("performed") is False


def test_every_mitm_result_has_evidence():
    ctx = _ctx("mitm", targets=["https://testssl.sh"], params={})
    for r in get_engine("mitm").run(ctx):
        if r.status == "unavailable":
            continue
        assert r.evidence, f"{r.check_id} returned no evidence"


# ------------------------------------------------------------------- FIX 3 ---
def test_social_campaign_authorization_notice_has_evidence():
    """SOC-03b must attach an evidence record.

    Regression: it emitted data= but evidence=[], so the report showed the
    finding with no supporting artefact.
    """
    ctx = _ctx("social_engineering", targets=["example.com"], params={})
    results = get_engine("social_engineering").run(ctx)
    soc03b = next((r for r in results if r.check_id == "SOC-03b"), None)
    if soc03b is None:
        pytest.skip("SOC-03b only fires when no authorization_ref is supplied")
    assert soc03b.evidence, "SOC-03b must carry an evidence record"


def test_social_authorization_supplied_silences_notice():
    ctx = _ctx("social_engineering", targets=["example.com"],
               params={"authorization_ref": "ENG-2026-001"})
    results = get_engine("social_engineering").run(ctx)
    assert not any(r.check_id == "SOC-03b" for r in results), (
        "SOC-03b must not fire when an authorization reference was supplied"
    )


# ------------------------------------------------- platform-wide invariants ---
def test_no_engine_contradicts_status_and_source():
    """status="unavailable" and source="unavailable" must agree both ways."""
    plan = {
        "mitm": (["https://testssl.sh"], {}),
        "physical_security": (["site-a"], {}),
        "hardware_security": (["127.0.0.1"], {}),
        "social_engineering": (["example.com"], {}),
        "mobile_security": (["127.0.0.1"], {}),
        "webapp": (["http://127.0.0.1:8099"], {}),
    }
    for module, (targets, params) in plan.items():
        for r in get_engine(module).run(_ctx(module, targets=targets, params=params)):
            assert r.status in VALID_STATUS, f"{module}/{r.check_id}: {r.status!r}"
            assert r.source in VALID_SOURCE, f"{module}/{r.check_id}: {r.source!r}"
            if r.source == "unavailable":
                assert r.status == "unavailable", (
                    f"{module}/{r.check_id}: source=unavailable but "
                    f"status={r.status!r}"
                )
            if r.status == "unavailable":
                assert r.description, (
                    f"{module}/{r.check_id}: unavailable without a stated reason"
                )


def test_every_result_has_a_title_and_description():
    plan = {
        "mitm": (["https://testssl.sh"], {}),
        "physical_security": (["site-a"], {}),
        "social_engineering": (["example.com"], {}),
    }
    for module, (targets, params) in plan.items():
        for r in get_engine(module).run(_ctx(module, targets=targets, params=params)):
            assert r.title, f"{module}/{r.check_id} has no title"
            assert r.description, f"{module}/{r.check_id} has no description"
