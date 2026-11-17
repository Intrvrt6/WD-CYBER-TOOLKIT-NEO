"""Report-integrity regression tests.

A penetration report must never imply that a check ran when it did not. These
tests lock the three-state checklist (executed / not executed / not reached) and
the persisted-status plumbing that makes it possible.

Background: section 4 of the report used to render every declared check as
"[x] executed", so an unavailable check (Suricata/Zeek absent -> NET-08) looked
like a successful run and the report overstated coverage.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def assessment_with_unavailable(db):
    """A stored assessment holding one executed and one unavailable finding."""
    from backend.database import Assessment, Finding

    a = Assessment(name="report integrity", template="network_pentest",
                   module="network", mode="live", intensity="light",
                   targets=["127.0.0.1"], status="completed", operator="tester",
                   risk_score=1.0,
                   summary={
                       "findings": 2, "failed": 1, "unavailable": 1,
                       "worst_severity": "low",
                       "checks_expected": ["NET-01", "NET-08"],
                       "checks_reported": ["NET-01", "NET-08"],
                       "coverage": {"declared": 2, "reported": 2, "missing": [],
                                    "percent": 100.0,
                                    "unavailable_checks": ["NET-08"]},
                       "by_severity": {"low": 1, "info": 1},
                       "by_status": {"fail": 1, "unavailable": 1},
                       "by_source": {"live": 1, "unavailable": 1},
                       "duration_s": 1.0,
                   })
    db.add(a)
    db.commit()

    db.add(Finding(assessment_id=a.id, title="Host discovery completed",
                   severity="info", status="info", description="probed 1 host",
                   evidence_source="live", check_id="NET-01",
                   evidence=[{"type": "other", "summary": "nmap"}]))
    db.add(Finding(assessment_id=a.id, title="Intrusion detection integration",
                   severity="info", status="unavailable",
                   description="Neither Suricata nor Zeek is installed.",
                   evidence_source="unavailable", check_id="NET-08", evidence=[]))
    db.commit()
    return a


# ---------------------------------------------------- persisted status ------ def
def test_findings_for_returns_stored_status(db, assessment_with_unavailable):
    """The API must report the stored verdict, not guess it from severity."""
    from backend import orchestrator

    rows = orchestrator.findings_for(db, assessment_with_unavailable.id)
    by_id = {r["check_id"]: r for r in rows}
    assert by_id["NET-01"]["status"] == "info"
    assert by_id["NET-08"]["status"] == "unavailable", (
        "an unavailable check must not be reported as 'info'"
    )


def test_finding_status_is_persisted_not_derived(db, assessment_with_unavailable):
    from backend.database import Finding

    rows = db.query(Finding).filter(Finding.assessment_id == assessment_with_unavailable.id).all()
    statuses = {r.check_id: r.status for r in rows}
    assert statuses["NET-08"] == "unavailable"


# ------------------------------------------------- three-state checklist ---- def
def test_markdown_marks_unavailable_as_not_executed(db, assessment_with_unavailable):
    from backend.reports import generator

    md = generator.render_markdown(generator.build_report_data(db, assessment_with_unavailable.id, "en"))
    assert "- [x] `NET-01`" in md
    assert "- [!] `NET-08`" in md, "unavailable check must be marked [!], not [x]"
    assert "Not executed" in md
    assert "Neither Suricata nor Zeek is installed." in md, "the reason must be shown"


def test_markdown_reports_coverage_summary(db, assessment_with_unavailable):
    from backend.reports import generator

    md = generator.render_markdown(generator.build_report_data(db, assessment_with_unavailable.id, "en"))
    assert "1 of 2 declared check(s) executed; 1 could not run." in md


def test_indonesian_report_localises_the_checklist(db, assessment_with_unavailable):
    from backend.reports import generator

    md = generator.render_markdown(generator.build_report_data(db, assessment_with_unavailable.id, "id"))
    assert "- [!] `NET-08`" in md
    assert "Tidak dieksekusi" in md
    assert "tidak dapat dijalankan" in md


def test_pdf_renders_without_error(db, assessment_with_unavailable):
    from backend.reports import generator

    pdf = generator.render_pdf(generator.build_report_data(db, assessment_with_unavailable.id, "en"))
    assert pdf[:4] == b"%PDF"
    assert len(pdf) > 2000


def test_html_renders_and_includes_findings(db, assessment_with_unavailable):
    from backend.reports import generator

    html = generator.render_html(generator.build_report_data(db, assessment_with_unavailable.id, "en"))
    assert "<html" in html.lower()
    assert "Intrusion detection integration" in html


# ------------------------------------------------ twelve required sections ---
def test_all_twelve_sections_present_en(db, assessment_with_unavailable):
    from backend.reports import generator

    md = generator.render_markdown(generator.build_report_data(db, assessment_with_unavailable.id, "en"))
    for heading in ("1. Executive Summary", "2. Scope", "3. Rules of Engagement",
                    "4. Methodology and Execution", "5. Tools and Versions",
                    "6. Findings", "7. CVSS Scores", "8. Evidence",
                    "9. Business Impact", "10. Remediation",
                    "11. Retesting Results", "12. Conclusion"):
        assert f"## {heading}" in md, f"missing section: {heading}"


def test_all_twelve_sections_present_id(db, assessment_with_unavailable):
    from backend.reports import generator

    md = generator.render_markdown(generator.build_report_data(db, assessment_with_unavailable.id, "id"))
    for heading in ("1. Ringkasan Eksekutif", "2. Ruang Lingkup", "3. Aturan Keterlibatan",
                    "4. Metodologi dan Eksekusi", "5. Perangkat dan Versi",
                    "6. Temuan", "7. Skor CVSS", "8. Bukti", "9. Dampak Bisnis",
                    "10. Rekomendasi Perbaikan", "11. Hasil Uji Ulang", "12. Kesimpulan"):
        assert f"## {heading}" in md, f"missing section: {heading}"
