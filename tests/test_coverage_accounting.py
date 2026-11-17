"""Coverage bookkeeping must never contradict the findings it reports.

Regression for a real defect found on the v1.2.1 tree: `CAN-05` (anomaly
detection) EXECUTED and produced five failing findings (CAN-05a..CAN-05e), yet
the report printed

    - [ ] `CAN-05` - Not executed
    8 of 9 declared check(s) executed; 1 could not run.

while five CAN-05 findings sat in the same report. Cause: the parent/suffix rule
was `check_id.rstrip("0123456789") == declared_id`, which can never match an
alphabetic suffix ("CAN-05a" stays "CAN-05a"), so a check that only emits derived
ids was declared missing. The platform promise is that the report never
overstates coverage; under-reporting an executed check is the same broken
invariant from the other side, because the checklist and the findings table
disagree.
"""
from __future__ import annotations


from backend import coverage as cov

DECLARED = ["CAN-01", "CAN-05", "CAN-06", "CAN-10"]


# ---------------------------------------------------------------- belongs -- def
def test_exact_id_belongs():
    assert cov.belongs("CAN-05", "CAN-05")


def test_alphabetic_and_index_suffixes_belong():
    """Derived ids in the real tree: CAN-05a..e, CAN-06b, NET-02b, NET-05c."""
    for produced in ("CAN-05a", "CAN-05e", "CAN-05-b"):
        assert cov.belongs(produced, "CAN-05"), produced
    assert cov.belongs("CAN-06b", "CAN-06")
    assert cov.belongs("NET-02b", "NET-02")
    assert cov.belongs("NET-05c", "NET-05")


def test_numeric_prefix_is_not_a_suffix_match():
    """`CAN-1` must not be satisfied by `CAN-10` (the loose-prefix failure mode)."""
    assert not cov.belongs("CAN-10", "CAN-1")
    assert not cov.belongs("NET-10", "NET-1")


def test_unrelated_ids_do_not_belong():
    assert not cov.belongs("CAN-06", "CAN-05")
    assert not cov.belongs("NET-05", "CAN-05")
    assert not cov.belongs("CAN-05toolong", "CAN-05")
    assert not cov.belongs("", "CAN-05")


# ------------------------------------------------------- declared_reported -- def
def test_executed_check_with_only_derived_ids_is_reported():
    """The exact CAN-05 regression: five derived ids must mark CAN-05 executed."""
    produced = ["CAN-01", "CAN-05a", "CAN-05b", "CAN-05c", "CAN-05d", "CAN-05e",
                "CAN-06", "CAN-06b", "CAN-10"]
    reported = cov.declared_reported(DECLARED, produced)
    assert "CAN-05" in reported, "CAN-05 executed but was reported as missing"
    assert cov.declared_missing(DECLARED, produced) == []


def test_partial_run_still_reports_the_real_gap():
    produced = ["CAN-01", "CAN-05a"]
    assert cov.declared_reported(DECLARED, produced) == ["CAN-01", "CAN-05"]
    assert cov.declared_missing(DECLARED, produced) == ["CAN-06", "CAN-10"]


def test_strip_suffix_maps_derived_back_to_parent():
    assert cov.strip_suffix("CAN-05c", DECLARED) == "CAN-05"
    assert cov.strip_suffix("CAN-01", DECLARED) == "CAN-01"
    assert cov.strip_suffix("NET-99", DECLARED) == "NET-99"


def test_reported_preserves_declared_order():
    produced = ["CAN-10", "CAN-01", "CAN-05b"]
    assert cov.declared_reported(DECLARED, produced) == ["CAN-01", "CAN-05", "CAN-10"]


# ------------------------------------------------------------- orchestrator -- def
def test_coverage_rollup_counts_derived_ids():
    """`_coverage()` must not claim a check is missing when it produced findings."""
    from backend import orchestrator
    from engines.base import Result

    class FakeEngine:
        checks = [("CAN-05", "anomaly detection"), ("CAN-06", "replay")]

    results = [
        Result(check_id="CAN-05a", title="t", description="d", severity="medium",
               status="fail", source="lab"),
        Result(check_id="CAN-05b", title="t", description="d", severity="low",
               status="fail", source="lab"),
        Result(check_id="CAN-06", title="t", description="d", severity="info",
               status="info", source="lab"),
        Result(check_id="CAN-06b", title="t", description="d", severity="medium",
               status="fail", source="lab"),
    ]
    out = orchestrator._coverage(FakeEngine, results)
    assert out["missing"] == []
    assert out["reported"] == out["declared"] == 2
    assert out["percent"] == 100.0


def test_coverage_rollup_maps_unavailable_derived_id_to_parent():
    """An unavailable derived id must still mark its declared parent not-executed."""
    from backend import orchestrator
    from engines.base import Result

    class FakeEngine:
        checks = [("CAN-05", "anomaly detection"), ("CAN-06", "replay")]

    results = [
        Result(check_id="CAN-05", title="t", description="d", severity="info",
               status="info", source="lab"),
        Result(check_id="CAN-06b", title="t", description="no can stack",
               severity="info", status="unavailable", source="unavailable"),
    ]
    out = orchestrator._coverage(FakeEngine, results)
    assert out["unavailable_checks"] == ["CAN-06"], out["unavailable_checks"]


# ------------------------------------------------------------------ report -- def
def test_report_does_not_mark_an_executed_check_unreached(db):
    """End-to-end: a stored summary that under-reports must not win over the findings."""
    from backend.database import Assessment, Finding
    from backend.reports import generator

    a = Assessment(name="can coverage", template="can_pentest", module="automotive_can",
                   mode="lab", intensity="light", targets=["can:wdcan0"],
                   status="completed", operator="tester", risk_score=4.08,
                   summary={
                       "findings": 2, "failed": 2, "unavailable": 0,
                       "worst_severity": "medium",
                       "checks_expected": ["CAN-05", "CAN-06"],
                       # the buggy snapshot: CAN-05 not recorded as reported
                       "checks_reported": ["CAN-06"],
                       "coverage": {"declared": 2, "reported": 1,
                                    "missing": ["CAN-05"], "percent": 50.0,
                                    "unavailable_checks": []},
                       "by_severity": {"medium": 2}, "by_status": {"fail": 2},
                       "by_source": {"lab": 2}, "duration_s": 1.0,
                   })
    db.add(a)
    db.commit()
    db.add(Finding(assessment_id=a.id, title="Anomaly detected - counter discontinuity",
                   severity="medium", status="fail", description="counter jumped",
                   evidence_source="lab", check_id="CAN-05a",
                   evidence=[{"type": "other", "summary": "simulator"}]))
    db.add(Finding(assessment_id=a.id, title="Anomaly detected - period deviation",
                   severity="medium", status="fail", description="period deviated",
                   evidence_source="lab", check_id="CAN-05b",
                   evidence=[{"type": "other", "summary": "simulator"}]))
    db.commit()

    data = generator.build_report_data(db, a.id, "en")
    assert "CAN-05" in data["reported"], (
        "the rendered findings prove CAN-05 executed, so the report must say so"
    )
    md = generator.render_markdown(data)
    assert "- [ ] `CAN-05`" not in md, "an executed check must not render as unreached"
    assert "- [x] `CAN-05`" in md
    assert "2 of 2 declared check(s) executed" in md
