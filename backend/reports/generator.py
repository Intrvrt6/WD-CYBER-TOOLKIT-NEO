"""Professional penetration report generation (EN + ID) as MD / HTML / PDF.

All twelve required sections are produced. Only observed data is included;
checks that could not run appear explicitly in the methodology section as
'not executed', with their reason.
"""
from __future__ import annotations

import datetime as dt
import html
import io
import os
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)
from sqlalchemy import select

from backend import config
from backend.database import Artifact, Assessment, Finding

I18N: dict[str, dict[str, str]] = {
    "en": {
        "title": "Penetration Test Report",
        "s1": "1. Executive Summary", "s2": "2. Scope", "s3": "3. Rules of Engagement",
        "s4": "4. Methodology and Execution", "s5": "5. Tools and Versions",
        "s6": "6. Findings", "s7": "7. CVSS Scores", "s8": "8. Evidence",
        "s9": "9. Business Impact", "s10": "10. Remediation", "s11": "11. Retesting Results",
        "s12": "12. Conclusion", "generated": "Generated", "operator": "Operator",
        "template": "Template", "mode": "Mode", "risk": "Risk score", "severity": "Severity",
        "asset": "Asset", "source": "Evidence source", "checklist": "Checklist coverage",
        "not_run": "Not executed", "repro": "Reproduction", "no_findings": "No findings recorded.",
        "id_label": "Finding", "status": "Status", "evidence_hash": "Evidence SHA-256",
        "scope_note": "Targets listed below were validated against the registered scope registry before execution.",
        "roe": "Testing was performed within an approved window with explicit operator authorization recorded in the immutable audit log.",
        "retest": "No retest has been executed for this assessment. Re-run the template after remediation to populate this section.",
        "concl": "Findings above reflect checks that actually executed; unavailable checks are listed explicitly and are not represented as passes.",
        "checklist_summary": "{executed} of {total} declared check(s) executed; {not_run} could not run.",
    },
    "id": {
        "title": "Laporan Uji Penetrasi",
        "s1": "1. Ringkasan Eksekutif", "s2": "2. Ruang Lingkup", "s3": "3. Aturan Keterlibatan",
        "s4": "4. Metodologi dan Eksekusi", "s5": "5. Perangkat dan Versi",
        "s6": "6. Temuan", "s7": "7. Skor CVSS", "s8": "8. Bukti",
        "s9": "9. Dampak Bisnis", "s10": "10. Rekomendasi Perbaikan", "s11": "11. Hasil Uji Ulang",
        "s12": "12. Kesimpulan", "generated": "Dibuat", "operator": "Operator",
        "template": "Template", "mode": "Mode", "risk": "Skor risiko", "severity": "Tingkat",
        "asset": "Aset", "source": "Sumber bukti", "checklist": "Cakupan checklist",
        "not_run": "Tidak dieksekusi", "repro": "Reproduksi", "no_findings": "Tidak ada temuan tercatat.",
        "id_label": "Temuan", "status": "Status", "evidence_hash": "SHA-256 Bukti",
        "scope_note": "Target di bawah ini divalidasi terhadap registri ruang lingkup sebelum eksekusi.",
        "roe": "Pengujian dilakukan dalam jendela yang disetujui dengan otorisasi operator eksplisit yang tercatat pada log audit.",
        "retest": "Belum ada uji ulang untuk asesmen ini. Jalankan kembali template setelah perbaikan untuk mengisi bagian ini.",
        "concl": "Temuan di atas mencerminkan pemeriksaan yang benar-benar dieksekusi; pemeriksaan yang tidak tersedia dicantumkan eksplisit dan tidak dianggap lulus.",
        "checklist_summary": "{executed} dari {total} pemeriksaan yang dideklarasikan dieksekusi; {not_run} tidak dapat dijalankan.",
    },
}

SEV_COLORS = {"critical": colors.HexColor("#7f1d1d"), "high": colors.HexColor("#b91c1c"),
              "medium": colors.HexColor("#b45309"), "low": colors.HexColor("#0369a1"),
              "info": colors.HexColor("#374151")}


def _t(lang: str, key: str) -> str:
    return I18N.get(lang, I18N["en"]).get(key, key)


def build_report_data(db, assessment_id: str, lang: str = "en") -> dict[str, Any]:
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise KeyError("assessment not found")
    findings = db.execute(select(Finding).where(Finding.assessment_id == assessment_id)
                          .order_by(Finding.created_at.asc())).scalars().all()
    arts = db.execute(select(Artifact).where(Artifact.assessment_id == assessment_id)).scalars().all()
    from backend import capabilities
    caps = capabilities.report()
    tools = {k: v for k, v in caps.get("cli_tools", {}).items() if v.get("present")}
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(findings, key=lambda f: (sev_rank.get(f.severity, 9), f.check_id))
    summary = a.summary or {}
    return {
        "assessment": a, "findings": ordered, "artifacts": arts, "lang": lang,
        "tools": tools, "summary": summary,
        "expected": summary.get("checks_expected") or [],
        "reported": summary.get("checks_reported") or [],
        "unavailable": (summary.get("coverage") or {}).get("unavailable_checks") or [],
        "unavailable_reasons": {f.check_id: f.description for f in ordered
                                if f.status == "unavailable" and f.check_id},
    }


def _impact_text(f: Finding, lang: str) -> str:
    if f.severity in ("critical", "high"):
        return ("Dampak tinggi: eksploitasi dapat menyebabkan kompromi pada aset yang diuji."
                if lang == "id" else
                "High impact: exploitation can lead to compromise of the assessed asset.")
    if f.severity == "medium":
        return ("Dampak sedang: melemahkan pertahanan dan mempermudah eskalasi."
                if lang == "id" else
                "Moderate impact: weakens defences and eases escalation.")
    if f.severity == "low":
        return ("Dampak rendah: kondisi higiene keamanan yang perlu diperbaiki."
                if lang == "id" else
                "Low impact: a security hygiene condition that should be corrected.")
    return ("Observasi informatif untuk konteks."
            if lang == "id" else "Informational observation for context.")


# ------------------------------------------------------------------- markdown --
def render_markdown(data: dict[str, Any]) -> str:
    a: Assessment = data["assessment"]
    lang = data["lang"]
    L = []
    ap = L.append
    ap(f"# {_t(lang,'title')} - {a.name}")
    ap("")
    ap(f"- **{_t(lang,'generated')}:** {dt.datetime.now(dt.timezone.utc).isoformat()}")
    ap(f"- **{_t(lang,'operator')}:** {a.operator}")
    ap(f"- **{_t(lang,'template')}:** {a.template} ({a.module})")
    ap(f"- **{_t(lang,'mode')}:** {a.mode} / intensity {a.intensity}")
    ap(f"- **{_t(lang,'risk')}:** {a.risk_score if a.risk_score is not None else 'n/a'}")
    ap(f"- **Status:** {a.status}")
    ap("")
    ap(f"## {_t(lang,'s1')}")
    s = data["summary"]
    ap(f"Assessment `{a.id}` executed {s.get('findings', len(data['findings']))} check result(s) "
       f"in {a.mode.upper()} mode. "
       f"{s.get('failed', 0)} result(s) reported a failing condition; "
       f"{s.get('unavailable', 0)} check(s) could not execute and are listed as unavailable, not as passes. "
       f"Worst observed severity: **{s.get('worst_severity','info')}**.")
    ap("")
    ap(f"## {_t(lang,'s2')}")
    ap(f"{_t(lang,'scope_note')}")
    ap("")
    for t in (a.targets or []):
        ap(f"- `{t}`")
    ap("")
    ap(f"## {_t(lang,'s3')}")
    ap(_t(lang, "roe"))
    ap(f"- Authorization id: `{a.authz_id or 'n/a'}`")
    ap("")
    ap(f"## {_t(lang,'s4')}")
    ap(f"### {_t(lang,'checklist')}")
    done = set(data["reported"])
    skipped = set(data.get("unavailable") or [])
    reasons = data.get("unavailable_reasons") or {}
    executed = [c for c in data["expected"] if c in done and c not in skipped]
    not_exec = [c for c in data["expected"] if c in skipped]
    unreached = [c for c in data["expected"] if c not in done and c not in skipped]
    for cid in executed:
        ap(f"- [x] `{cid}`")
    for cid in not_exec:
        why = (reasons.get(cid) or "").strip()
        why = (why[:200] + "...") if len(why) > 200 else why
        ap(f"- [!] `{cid}` - {_t(lang,'not_run')}" + (f": {why}" if why else ""))
    for cid in unreached:
        ap(f"- [ ] `{cid}` - {_t(lang,'not_run')}")
    ap("")
    ap(_t(lang, "checklist_summary").format(
        executed=len(executed),
        not_run=len(not_exec) + len(unreached),
        total=len(data["expected"]),
    ))
    ap("")
    ap(f"## {_t(lang,'s5')}")
    for name, info in sorted(data["tools"].items()):
        ap(f"- **{name}**: {info.get('version') or 'present'}")
    ap("")
    ap(f"## {_t(lang,'s6')}")
    if not data["findings"]:
        ap(_t(lang, "no_findings"))
    for i, f in enumerate(data["findings"], 1):
        ap(f"### {_t(lang,'id_label')} {i}: {f.title}")
        ap(f"- {_t(lang,'severity')}: **{f.severity}**")
        ap(f"- {_t(lang,'asset')}: `{f.asset or 'n/a'}`")
        ap(f"- {_t(lang,'source')}: `{f.evidence_source}`")
        ap(f"- Check: `{f.check_id}`")
        if f.cvss_score is not None:
            ap(f"- CVSS: {f.cvss_score} {f.cvss_vector or ''}")
        if f.cwe:
            ap(f"- CWE: {', '.join(f.cwe)}")
        ap("")
        ap(f.description or "")
        ap("")
        ap(f"**Impact:** {_impact_text(f, lang)}")
        ap("")
        if f.remediation:
            ap(f"**{_t(lang,'s10')}:** {f.remediation}")
            ap("")
        for ev in (f.evidence or []):
            if not isinstance(ev, dict):
                continue
            ap(f"**{_t(lang,'repro')}:** `{ev.get('command') or ev.get('summary') or ev.get('type')}`")
            out = (ev.get("stdout") or "")[:1200]
            if out:
                ap("```")
                ap(out)
                ap("```")
            ap("")
    ap(f"## {_t(lang,'s7')}")
    ap("| Check | Finding | Severity | CVSS | Vector |")
    ap("|---|---|---|---|---|")
    for f in data["findings"]:
        ap(f"| {f.check_id} | {f.title[:60]} | {f.severity} | {f.cvss_score if f.cvss_score is not None else '-'} | {f.cvss_vector or '-'} |")
    ap("")
    ap(f"## {_t(lang,'s8')}")
    if not data["artifacts"]:
        ap("No evidence artifacts were persisted for this assessment.")
    for art in data["artifacts"]:
        ap(f"- `{art.name}` ({art.kind}, {art.size} bytes) - {_t(lang,'evidence_hash')}: `{art.sha256 or 'n/a'}`")
        ap(f"  - path: `{art.path}`")
    ap("")
    ap(f"## {_t(lang,'s9')}")
    for f in data["findings"]:
        if f.severity != "info":
            ap(f"- **{f.severity.upper()}** {f.title}: {_impact_text(f, lang)}")
    ap("")
    ap(f"## {_t(lang,'s10')}")
    for f in data["findings"]:
        if f.remediation:
            ap(f"- `{f.check_id}` {f.remediation}")
    ap("")
    ap(f"## {_t(lang,'s11')}")
    ap(_t(lang, "retest"))
    ap("")
    ap(f"## {_t(lang,'s12')}")
    ap(_t(lang, "concl"))
    return "\n".join(L)


# ----------------------------------------------------------------------- html --
def render_html(data: dict[str, Any]) -> str:
    md = render_markdown(data)
    a: Assessment = data["assessment"]
    rows = []
    for f in data["findings"]:
        rows.append(
            f"<tr><td><span class='sev {f.severity}'>{html.escape(f.severity)}</span></td>"
            f"<td><code>{html.escape(f.check_id)}</code></td>"
            f"<td>{html.escape(f.title)}</td><td>{html.escape(f.asset or '-')}</td>"
            f"<td>{f.cvss_score if f.cvss_score is not None else '-'}</td>"
            f"<td>{html.escape(f.evidence_source)}</td></tr>")
    body = html.escape(md)
    return f"""<!doctype html><html lang='{data['lang']}'><head><meta charset='utf-8'>
<title>{html.escape(_t(data['lang'],'title'))} - {html.escape(a.name)}</title>
<style>
body{{background:#0b0f14;color:#d6e2ee;font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:32px}}
h1,h2,h3{{color:#5eead4;font-weight:600}} h1{{border-bottom:1px solid #1f2a37;padding-bottom:12px}}
table{{border-collapse:collapse;width:100%;margin:16px 0}} th,td{{border:1px solid #1f2a37;padding:8px;text-align:left}}
th{{background:#111827;color:#93c5fd}} code,pre{{background:#0f172a;color:#a5f3fc;padding:2px 4px;border-radius:3px}}
pre{{padding:12px;overflow:auto;border-left:3px solid #14b8a6}}
.sev{{padding:2px 8px;border-radius:3px;font-weight:700;color:#fff}}
.sev.critical{{background:#7f1d1d}} .sev.high{{background:#b91c1c}} .sev.medium{{background:#b45309}}
.sev.low{{background:#0369a1}} .sev.info{{background:#374151}}
.md{{white-space:pre-wrap;background:#0d131a;padding:20px;border:1px solid #1f2a37;border-radius:6px}}
</style></head><body>
<h1>{html.escape(_t(data['lang'],'title'))}</h1>
<p><strong>{html.escape(a.name)}</strong> &middot; {html.escape(a.template)} &middot; mode {html.escape(a.mode)} &middot; risk {a.risk_score if a.risk_score is not None else 'n/a'}</p>
<h2>{html.escape(_t(data['lang'],'s6'))}</h2>
<table><thead><tr><th>{html.escape(_t(data['lang'],'severity'))}</th><th>Check</th><th>Title</th>
<th>{html.escape(_t(data['lang'],'asset'))}</th><th>CVSS</th><th>{html.escape(_t(data['lang'],'source'))}</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=6>No findings recorded.</td></tr>'}</tbody></table>
<h2>Full report</h2><div class='md'>{body}</div></body></html>"""


# ------------------------------------------------------------------------ pdf --
def render_pdf(data: dict[str, Any]) -> bytes:
    a: Assessment = data["assessment"]
    lang = data["lang"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=16 * mm,
                            title=f"{_t(lang,'title')} - {a.name}", author="WD CYBER TOOLKIT NEO")
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("H1x", parent=ss["Heading1"], textColor=colors.HexColor("#0f766e"), fontSize=16, spaceAfter=8)
    H2 = ParagraphStyle("H2x", parent=ss["Heading2"], textColor=colors.HexColor("#155e75"), fontSize=12, spaceBefore=10, spaceAfter=6)
    H3 = ParagraphStyle("H3x", parent=ss["Heading3"], fontSize=10.5, textColor=colors.HexColor("#111827"), spaceBefore=8, spaceAfter=4)
    B = ParagraphStyle("Bx", parent=ss["BodyText"], fontSize=9, leading=12.5, alignment=TA_LEFT)
    SMALL = ParagraphStyle("Sx", parent=B, fontSize=7.6, leading=10, textColor=colors.HexColor("#374151"))
    MONO = ParagraphStyle("Mx", parent=B, fontName="Courier", fontSize=7.2, leading=9.2,
                          backColor=colors.HexColor("#f3f4f6"), borderPadding=4)
    story: list = []
    story.append(Paragraph(_t(lang, "title"), H1))
    story.append(Paragraph(html.escape(a.name), H2))
    meta = [["Field", "Value"],
            [_t(lang, "generated"), dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
            [_t(lang, "operator"), a.operator],
            [_t(lang, "template"), f"{a.template} ({a.module})"],
            [_t(lang, "mode"), f"{a.mode} / {a.intensity}"],
            [_t(lang, "risk"), str(a.risk_score if a.risk_score is not None else "n/a")],
            ["Status", a.status], ["Assessment ID", a.id]]
    t = Table(meta, colWidths=[45 * mm, 120 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                           ("FONTSIZE", (0, 0), (-1, -1), 8.4),
                           ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")])]))
    story.append(t)
    s = data["summary"]

    story.append(Paragraph(_t(lang, "s1"), H2))
    story.append(Paragraph(html.escape(
        f"Assessment {a.id} executed {s.get('findings', 0)} check result(s) in {a.mode.upper()} mode. "
        f"{s.get('failed', 0)} result(s) reported a failing condition; {s.get('unavailable', 0)} check(s) "
        f"could not execute and are recorded as unavailable, not as passes. Worst observed severity: "
        f"{s.get('worst_severity', 'info')}."), B))
    by_sev = s.get("by_severity") or {}
    if by_sev:
        sev_rows = [["Severity", "Count"]] + [[k, str(v)] for k, v in
                                                 sorted(by_sev.items(), key=lambda kv: kv[0])]
        st = Table(sev_rows, colWidths=[45 * mm, 25 * mm])
        st.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#155e75")),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("FONTSIZE", (0, 0), (-1, -1), 8),
                                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db"))]))
        story.append(Spacer(1, 4)); story.append(st)

    story.append(Paragraph(_t(lang, "s2"), H2))
    story.append(Paragraph(html.escape(_t(lang, "scope_note")), B))
    for tg in (a.targets or []):
        story.append(Paragraph(f"&bull; {html.escape(str(tg))}", B))

    story.append(Paragraph(_t(lang, "s3"), H2))
    story.append(Paragraph(html.escape(_t(lang, "roe")), B))
    story.append(Paragraph(f"Authorization: {html.escape(a.authz_id or 'n/a')}", B))

    story.append(PageBreak())
    story.append(Paragraph(_t(lang, "s4"), H2))
    story.append(Paragraph(_t(lang, "checklist"), H3))
    done = set(data["reported"])
    skipped = set(data.get("unavailable") or [])
    for cid in data["expected"]:
        if cid in done and cid not in skipped:
            mark, note = "[x]", ""
        elif cid in skipped:
            mark, note = "[!]", f" - {_t(lang, 'not_run')}"
        else:
            mark, note = "[ ]", f" - {_t(lang, 'not_run')}"
        story.append(Paragraph(f"{mark} {html.escape(cid)}{html.escape(note)}", SMALL))

    story.append(Paragraph(_t(lang, "s5"), H2))
    for name, info in sorted(data["tools"].items()):
        story.append(Paragraph(f"{html.escape(name)}: {html.escape(str(info.get('version') or 'present'))}", SMALL))

    story.append(PageBreak())
    story.append(Paragraph(_t(lang, "s6"), H2))
    if not data["findings"]:
        story.append(Paragraph(_t(lang, "no_findings"), B))
    for i, f in enumerate(data["findings"], 1):
        block = [Paragraph(f"{_t(lang,'id_label')} {i}: {html.escape(f.title)}", H3)]
        badge = [[f.severity.upper(), f"CVSS {f.cvss_score if f.cvss_score is not None else 'n/a'}",
                  f"check {f.check_id}", f"source {f.evidence_source}"]]
        bt = Table(badge, colWidths=[24 * mm, 30 * mm, 40 * mm, 45 * mm])
        bt.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), SEV_COLORS.get(f.severity, colors.grey)),
                                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                                ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
                                ("FONTSIZE", (0, 0), (-1, -1), 7.4),
                                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db"))]))
        block.append(bt); block.append(Spacer(1, 3))
        if f.asset:
            block.append(Paragraph(f"<b>{_t(lang,'asset')}:</b> {html.escape(f.asset)}", SMALL))
        if f.cvss_vector:
            block.append(Paragraph(f"<b>CVSS vector:</b> {html.escape(f.cvss_vector)}", SMALL))
        if f.cwe:
            block.append(Paragraph(f"<b>CWE:</b> {html.escape(', '.join(f.cwe))}", SMALL))
        block.append(Paragraph(html.escape((f.description or "")[:4000]), B))
        block.append(Paragraph(f"<b>{_t(lang,'s9')}:</b> {html.escape(_impact_text(f, lang))}", B))
        if f.remediation:
            block.append(Paragraph(f"<b>{_t(lang,'s10')}:</b> {html.escape(f.remediation[:2000])}", B))
        for ev in (f.evidence or [])[:3]:
            if not isinstance(ev, dict):
                continue
            cmd = ev.get("command") or ev.get("summary") or ev.get("type") or ""
            out = (ev.get("stdout") or "")[:900]
            block.append(Paragraph(f"<b>{_t(lang,'repro')}:</b> {html.escape(str(cmd))}", SMALL))
            if out:
                block.append(Paragraph(html.escape(out).replace(" ", "&nbsp;"), MONO))
        story.append(KeepTogether(block[:2]))
        for b in block[2:]:
            story.append(b)
        story.append(Spacer(1, 7))

    story.append(PageBreak())
    story.append(Paragraph(_t(lang, "s7"), H2))
    rows = [["Check", "Finding", "Severity", "CVSS", "Vector"]]
    for f in data["findings"]:
        rows.append([f.check_id, f.title[:52], f.severity,
                     str(f.cvss_score if f.cvss_score is not None else "-"), (f.cvss_vector or "-")[:44]])
    st = Table(rows, colWidths=[20 * mm, 62 * mm, 18 * mm, 14 * mm, 51 * mm], repeatRows=1)
    st.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#155e75")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                            ("FONTSIZE", (0, 0), (-1, -1), 7.2),
                            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(st)

    story.append(Paragraph(_t(lang, "s8"), H2))
    if not data["artifacts"]:
        story.append(Paragraph("No evidence artifacts were persisted for this assessment.", SMALL))
    for art in data["artifacts"]:
        story.append(Paragraph(
            f"{html.escape(art.name)} ({html.escape(art.kind)}, {art.size} B)<br/>"
            f"SHA-256: {html.escape(art.sha256 or 'n/a')}<br/>{html.escape(art.path)}", SMALL))

    story.append(Paragraph(_t(lang, "s9"), H2))
    for f in data["findings"]:
        if f.severity != "info":
            story.append(Paragraph(f"<b>{f.severity.upper()}</b> {html.escape(f.title)}: "
                                   f"{html.escape(_impact_text(f, lang))}", B))
    story.append(Paragraph(_t(lang, "s10"), H2))
    for f in data["findings"]:
        if f.remediation:
            story.append(Paragraph(f"&bull; {html.escape(f.check_id)} {html.escape(f.remediation[:600])}", B))
    story.append(Paragraph(_t(lang, "s11"), H2))
    story.append(Paragraph(html.escape(_t(lang, "retest")), B))
    story.append(Paragraph(_t(lang, "s12"), H2))
    story.append(Paragraph(html.escape(_t(lang, "concl")), B))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(18 * mm, 10 * mm, f"WD CYBER TOOLKIT NEO - {a.name}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


FORMATS = {"md": "text/markdown", "html": "text/html", "pdf": "application/pdf"}


def render(db, assessment_id: str, fmt: str = "pdf", lang: str = "en") -> tuple[bytes | str, str, str]:
    data = build_report_data(db, assessment_id, lang)
    if fmt == "md":
        return render_markdown(data), "text/markdown; charset=utf-8", "md"
    if fmt == "html":
        return render_html(data), "text/html; charset=utf-8", "html"
    return render_pdf(data), "application/pdf", "pdf"


def save(db, assessment_id: str, fmt: str = "pdf", lang: str = "en") -> str:
    content, _mime, ext = render(db, assessment_id, fmt, lang)
    config.ensure_dirs()
    path = os.path.join(str(config.REPORT_DIR), f"{assessment_id}_{lang}.{ext}")
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode, **({} if isinstance(content, bytes) else {"encoding": "utf-8"})) as fh:
        fh.write(content)
    return path
