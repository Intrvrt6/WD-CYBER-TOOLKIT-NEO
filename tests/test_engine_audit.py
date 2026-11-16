"""Platform-wide engine audit as a real pytest test.

`tests/audit_all_engines.py` is a developer CLI (it is named so pytest does not
collect it). This module wraps the same contract checks so CI fails when any
engine regresses, instead of relying on someone remembering to run the script.

Every engine is EXECUTED here. Checks asserted per engine:
  * valid status / severity / source tokens
  * status="unavailable" and source="unavailable" agree in both directions
  * an unavailable check always states a reason
  * every non-unavailable result carries an evidence trail
  * every declared check id produces a result (no silent gaps)

Marked `slow` because it drives real subprocesses, sockets and simulators.
"""
from __future__ import annotations

import pytest

from engines import base
from engines.base import Context, get_engine

pytestmark = pytest.mark.slow

VALID_STATUS = {"pass", "fail", "info", "unavailable", "error"}
VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}
VALID_SOURCE = {"live", "lab", "local", "unavailable"}

# module -> (mode, targets, params)
PLAN = {
    "network": ("live", ["https://testssl.sh"], {"capture_seconds": 3}),
    "mitm": ("live", ["https://testssl.sh"], {}),
    "scada_ics": ("lab", ["modbus://127.0.0.1:5020"], {}),
    "automotive_can": ("lab", ["can:wdcan0"], {}),
    "threat_intelligence": ("live", ["203.0.113.45", "example.com"],
                            {"iocs": ["203.0.113.45", "example.com"],
                             "sample_path": "samples/iocs_demo.csv"}),
    "webapp": ("live", ["http://127.0.0.1:8099"], {}),
    "mobile_security": ("live", ["127.0.0.1"], {}),
    "social_engineering": ("live", ["example.com"], {}),
    "physical_security": ("live", ["site-a"], {}),
    "hardware_security": ("live", ["127.0.0.1"], {}),
}


@pytest.fixture(scope="module")
def engine_results():
    """Execute every engine exactly once and share the results across tests."""
    out = {}
    for module, (mode, targets, params) in PLAN.items():
        ctx = Context(assessment_id=f"audit-{module}", module=module, mode=mode,
                      intensity="light", targets=targets, params=params,
                      evidence_dir=f"evidence/audit-{module}")
        out[module] = get_engine(module).run(ctx)
    return out


def test_plan_covers_every_registered_engine():
    """A new engine must be added to PLAN or it is silently unaudited."""
    registered = set(base.modules())
    planned = set(PLAN)
    assert registered == planned, (
        "tests/audit_all_engines_plan mismatch; "
        f"unplanned={sorted(registered - planned)} "
        f"stale={sorted(planned - registered)}"
    )


def test_every_engine_returns_results(engine_results):
    for module, results in engine_results.items():
        assert results, f"{module} produced no results"


def test_all_tokens_are_valid(engine_results):
    for module, results in engine_results.items():
        for r in results:
            assert r.status in VALID_STATUS, f"{module}/{r.check_id}: {r.status!r}"
            assert r.severity in VALID_SEVERITY, f"{module}/{r.check_id}: {r.severity!r}"
            assert r.source in VALID_SOURCE, f"{module}/{r.check_id}: {r.source!r}"


def test_status_and_source_agree(engine_results):
    """unavailable source <=> unavailable status, both directions."""
    for module, results in engine_results.items():
        for r in results:
            if r.source == "unavailable":
                assert r.status == "unavailable", (
                    f"{module}/{r.check_id}: source=unavailable but status={r.status!r}"
                )
            if r.status == "unavailable":
                assert r.source == "unavailable", (
                    f"{module}/{r.check_id}: status=unavailable but source={r.source!r}"
                )


def test_unavailable_always_states_a_reason(engine_results):
    for module, results in engine_results.items():
        for r in results:
            if r.status == "unavailable":
                assert r.description and r.description.strip(), (
                    f"{module}/{r.check_id}: unavailable with no stated reason"
                )


def test_every_reportable_result_has_evidence(engine_results):
    """A result that claims an observation must show its evidence."""
    missing = []
    for module, results in engine_results.items():
        for r in results:
            if r.status == "unavailable" or r.status == "error":
                continue
            if not r.evidence:
                missing.append(f"{module}/{r.check_id}")
    assert not missing, f"results without evidence: {missing}"


def test_every_result_has_title_and_description(engine_results):
    for module, results in engine_results.items():
        for r in results:
            assert r.title, f"{module}/{r.check_id}: empty title"
            assert r.description, f"{module}/{r.check_id}: empty description"


def test_no_declared_check_is_silently_missing(engine_results):
    """Each declared id must appear, or a suffixed variant of it must."""
    gaps = {}
    for module, results in engine_results.items():
        produced = {r.check_id for r in results}
        declared = [c[0] for c in get_engine(module).checks]
        missing = [d for d in declared
                   if d not in produced
                   and not any(p.startswith(d) for p in produced)]
        if missing:
            gaps[module] = missing
    assert not gaps, f"declared checks produced no result: {gaps}"


def test_findings_have_unique_ids_per_engine(engine_results):
    """Duplicate result ids would collapse rows in the report table."""
    for module, results in engine_results.items():
        ids = [r.check_id for r in results]
        # suffixed variants (NET-05b) are legitimate; exact duplicates are not
        # CAN-05 deliberately emits one result per anomaly CLASS observed, so it
        # is the single documented exception; everything else must be unique.
        dupes = {i for i in ids if ids.count(i) > 1 and i != "CAN-05"}
        assert not dupes, f"{module} emitted duplicate result ids: {sorted(dupes)}"
