"""Module H - Physical Security.

Honest by construction: a physical assessment is checklist-driven and must record
OBSERVATIONS, never invented results.  This engine evaluates a real checklist
against operator-supplied observations:

  * params["checklist_path"]  optional YAML/JSON checklist (falls back to the
                              in-code default checklist of 20 controls)
  * params["observations"]    {checklist_id: {answer: pass|fail|na, note, evidence_ref}}

An item with no observation is emitted as status="info", source="unavailable"
with the note "not observed - requires on-site operator input".  Aggregate
scores (PHY-06) are computed ONLY over observed items, and the result is marked
incomplete whenever any applicable item is unobserved - the scoring formula is
stated in the result so the number is auditable.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
from typing import Any

from backend import runner
from engines.base import Context, Result, unavailable

# ---------------------------------------------------------------------------
# Default checklist: 20 controls over 5 domains.  Each item states the control,
# the question an assessor must answer, and the evidence that answer requires.
# ---------------------------------------------------------------------------
DEFAULT_CHECKLIST_VERSION = "wd-phy-2026.1"
DEFAULT_CHECKLIST: list[dict] = [
    # --- access control -----------------------------------------------------
    {"id": "AC-01", "domain": "access_control", "control": "Perimeter door control",
     "question": "Is every external door controlled by an electronic access-control reader?",
     "expected_evidence": "Door schedule with reader IDs and a photo of each reader"},
    {"id": "AC-02", "domain": "access_control", "control": "Tailgating mitigation",
     "question": "Is there a turnstile, mantrap or manned point preventing tailgating at the main entrance?",
     "expected_evidence": "Photo of the entrance configuration and the posted anti-tailgating notice"},
    {"id": "AC-03", "domain": "access_control", "control": "Access log retention",
     "question": "Are access-control events retained for at least 90 days and reviewable?",
     "expected_evidence": "Exported access log sample showing at least 90 days of history"},
    {"id": "AC-04", "domain": "access_control", "control": "Leaver deprovisioning",
     "question": "Is there documented proof that access cards are revoked within 24h of a leaver?",
     "expected_evidence": "Two recent leaver records matched to card-revocation timestamps"},
    {"id": "AC-05", "domain": "access_control", "control": "Restricted-area authorisation",
     "question": "Are server/comms rooms restricted to a named, reviewed authorisation list?",
     "expected_evidence": "Current authorised-person list with a review date and approver"},
    # --- CCTV ---------------------------------------------------------------
    {"id": "CV-01", "domain": "cctv", "control": "Coverage of entry/exit points",
     "question": "Do cameras cover every external entrance and exit with identifiable image quality?",
     "expected_evidence": "Camera-to-door coverage map plus a still frame showing a face or plate"},
    {"id": "CV-02", "domain": "cctv", "control": "Recording retention",
     "question": "Is recorded footage retained for at least 30 days?",
     "expected_evidence": "NVR storage/retention setting screenshot showing a >=30 day window"},
    {"id": "CV-03", "domain": "cctv", "control": "Camera health monitoring",
     "question": "Is there alerting when a camera goes offline or its view is obstructed?",
     "expected_evidence": "Alert rule configuration and one example offline/obscured notification"},
    {"id": "CV-04", "domain": "cctv", "control": "Time synchronisation",
     "question": "Are CCTV recorder clocks synchronised to a trusted time source?",
     "expected_evidence": "NTP setting screen and the recorder clock compared to a reference clock"},
    {"id": "CV-05", "domain": "cctv", "control": "Footage access control",
     "question": "Is footage export restricted to named staff and logged?",
     "expected_evidence": "Export permission list and a sample export audit entry"},
    # --- visitor management -------------------------------------------------
    {"id": "VM-01", "domain": "visitor_management", "control": "Visitor sign-in",
     "question": "Are all visitors signed in and issued an identifiable badge?",
     "expected_evidence": "Recent visitor log pages and a photo of the badge design"},
    {"id": "VM-02", "domain": "visitor_management", "control": "Identity verification",
     "question": "Is visitor identity verified against photo ID before entry?",
     "expected_evidence": "Written procedure plus a redacted example verification record"},
    {"id": "VM-03", "domain": "visitor_management", "control": "Escort policy",
     "question": "Are visitors escorted in secure areas, or is unescorted access formally approved?",
     "expected_evidence": "Escort policy document and a signed unescorted-access approval"},
    {"id": "VM-04", "domain": "visitor_management", "control": "Badge return",
     "question": "Is there proof that visitor badges are collected on exit?",
     "expected_evidence": "Badge-return column completed in the visitor log for the last week"},
    # --- tamper evidence ----------------------------------------------------
    {"id": "TE-01", "domain": "tamper_evidence", "control": "Enclosure seals",
     "question": "Do server/comms cabinets carry serialised tamper-evident seals?",
     "expected_evidence": "Photo of a sealed cabinet showing the seal serial number"},
    {"id": "TE-02", "domain": "tamper_evidence", "control": "Seal register",
     "question": "Is there a current register of seal serial numbers with periodic verification?",
     "expected_evidence": "Seal register with the most recent verification date and initials"},
    {"id": "TE-03", "domain": "tamper_evidence", "control": "Cable and port protection",
     "question": "Are exposed network ports and cabling protected against unauthorised connection?",
     "expected_evidence": "Photo of locked port shutters or cable containment in public areas"},
    {"id": "TE-04", "domain": "tamper_evidence", "control": "Tamper review cadence",
     "question": "Are seals inspected on a documented schedule (at least monthly)?",
     "expected_evidence": "Inspection schedule with the last two completed entries"},
    # --- incident documentation ---------------------------------------------
    {"id": "ID-01", "domain": "incident_documentation", "control": "Physical incident register",
     "question": "Is there a register recording physical security incidents with closure evidence?",
     "expected_evidence": "Register export showing at least one closed incident with evidence attached"},
    {"id": "ID-02", "domain": "incident_documentation", "control": "Drill and test records",
     "question": "Is there a record of a physical security exercise within the last 12 months?",
     "expected_evidence": "Exercise report with date, participants and lessons learned"},
]

VALID_ANSWERS = {"pass", "fail", "na"}


class PhysicalEngine:
    module = "physical_security"
    title = "Module H - Physical Security"
    description = ("Checklist-driven physical assessment: access control, CCTV, visitor management, tamper "
                   "evidence and incident documentation, scored only from recorded on-site observations.")
    checks = [
        ("PHY-01", "Access control audit", True),
        ("PHY-02", "CCTV assessment checklist", True),
        ("PHY-03", "Visitor management review", True),
        ("PHY-04", "Tamper evidence inspection", True),
        ("PHY-05", "Physical incident documentation template", True),
        ("PHY-06", "Aggregate physical risk score", True),
    ]

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        self._checklist, self._checklist_meta = load_checklist(ctx)
        self._obs, self._obs_errors = load_observations(ctx.params.get("observations"))
        self._source = ("local" if self._obs else "unavailable")
        steps = [("PHY-01", self.access_control), ("PHY-02", self.cctv),
                 ("PHY-03", self.visitor_management), ("PHY-04", self.tamper_evidence),
                 ("PHY-05", self.incident_documentation), ("PHY-06", self.aggregate_score)]
        for i, (cid, fn) in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("PHY-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining physical checks were not executed.", source="local"))
                break
            try:
                fn(ctx)
            except Exception as exc:
                ctx.add(Result(f"{cid}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    # ------------------------------------------------------------ helpers ---
    def _domain_items(self, domain: str) -> list[dict]:
        return [i for i in self._checklist if i.get("domain") == domain]

    def _evaluate(self, item: dict) -> dict:
        oid = item["id"]
        obs = self._obs.get(oid)
        row = {"id": oid, "domain": item.get("domain"), "control": item.get("control"),
               "question": item.get("question"), "expected_evidence": item.get("expected_evidence")}
        if obs is None:
            row.update({"answer": None, "status": "info", "source": "unavailable",
                        "note": "not observed - requires on-site operator input"})
            return row
        answer = obs.get("answer")
        if answer not in VALID_ANSWERS:
            row.update({"answer": answer, "status": "error", "source": "unavailable",
                        "note": f"invalid answer {answer!r} (expected pass|fail|na)"})
            return row
        if answer == "na":
            row.update({"answer": answer, "status": "info", "source": "local",
                        "note": obs.get("note") or "assessor marked not applicable"})
        else:
            row.update({"answer": answer, "status": "pass" if answer == "pass" else "fail",
                        "source": "local",
                        "severity": "info" if answer == "pass" else "medium"})
        row["note"] = obs.get("note") or row.get("note") or ""
        row["evidence_ref"] = obs.get("evidence_ref")
        row["observed_by"] = obs.get("observed_by")
        row["observed_at"] = obs.get("observed_at")
        return row

    def _emit_domain(self, ctx: Context, check_id: str, title: str, domain: str,
                     fail_severity: str, cvss: float, description_extra: str) -> None:
        items = self._domain_items(domain)
        if not items:
            ctx.add(unavailable(check_id, title,
                                f"The active checklist defines no control in the '{domain}' domain.", ))
            return
        rows = [self._evaluate(i) for i in items]
        observed = [r for r in rows if r["status"] in ("pass", "fail")]
        failed = [r for r in rows if r["status"] == "fail"]
        na = [r for r in rows if r["answer"] == "na"]
        unobs = [r for r in rows if r["status"] == "info" and r["answer"] is None]
        if observed:
            status = "fail" if failed else "pass"
            source = "local"
        else:
            status, source = "info", "unavailable"
        desc = (f"{len(items)} control(s) in '{domain}': {len(observed)} observed "
                f"({len(observed) - len(failed)} pass / {len(failed)} fail), "
                f"{len(na)} not applicable, {len(unobs)} not observed.")
        if failed:
            desc += " Failing: " + "; ".join(f"{r['id']} {r['control']}" for r in failed) + "."
        if unobs:
            desc += " Unobserved controls require on-site operator input."
        if description_extra:
            desc += " " + description_extra
        ctx.add(Result(check_id, title, status,
                       severity=fail_severity if failed else "info",
                       description=desc, asset=ctx.targets[0] if ctx.targets else "site",
                       source=source,
                       cvss_score=cvss if failed else None,
                       cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if failed else None,
                       cwe=["CWE-1263"] if failed else [],
                       remediation=(f"Remediate {', '.join(r['id'] for r in failed)} and record the on-site "
                                    f"evidence listed for each control.") if failed else
                                   (f"Collect the {len(unobs)} unobserved control(s) "
                                    f"({', '.join(r['id'] for r in unobs)}); this domain cannot be called "
                                    f"compliant until every applicable control is observed." if unobs else
                                    "All applicable controls were observed and passed; keep the evidence "
                                    "current at each review cycle."),
                       evidence=[{"type": "other", "summary": f"{domain} checklist evaluation", "items": rows}],
                       data={"domain": domain, "items": rows,
                             "observed": len(observed), "failed": failed, "na": na,
                             "unobserved": [r["id"] for r in unobs],
                             "checklist_version": self._checklist_meta.get("version"),
                             "checklist_source": self._checklist_meta.get("source")}))

    # ------------------------------------------------------------ PHY-01 ----
    def access_control(self, ctx: Context) -> None:
        self._emit_domain(ctx, "PHY-01", "Access control audit", "access_control",
                          "high", 6.1,
                          "Physical access bypass defeats logical controls that assume a trusted premises.")

    # ------------------------------------------------------------ PHY-02 ----
    def cctv(self, ctx: Context) -> None:
        self._emit_domain(ctx, "PHY-02", "CCTV assessment checklist", "cctv",
                          "medium", 5.0,
                          "CCTV is detective control only: it limits impact by enabling attribution and response.")

    # ------------------------------------------------------------ PHY-03 ----
    def visitor_management(self, ctx: Context) -> None:
        self._emit_domain(ctx, "PHY-03", "Visitor management review", "visitor_management",
                          "medium", 4.8,
                          "Unescorted or unverified visitors are the classic route to a rogue device on the LAN.")

    # ------------------------------------------------------------ PHY-04 ----
    def tamper_evidence(self, ctx: Context) -> None:
        self._emit_domain(ctx, "PHY-04", "Tamper evidence inspection", "tamper_evidence",
                          "medium", 5.2,
                          "Without seals a physical implant can be installed and removed without trace.")

    # ------------------------------------------------------------ PHY-05 ----
    def incident_documentation(self, ctx: Context) -> None:
        domain = "incident_documentation"
        items = self._domain_items(domain)
        rows = [self._evaluate(i) for i in items]
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        site = ctx.params.get("site_name") or (ctx.targets[0] if ctx.targets else "unspecified site")
        # Real, usable incident form (markdown) + machine-readable CSV header.
        md = incident_form_markdown(site, now, self._checklist_meta)
        csv_text = incident_form_csv(site, now)
        md_art = ctx.save_text("physical_incident_form.md", md)
        csv_art = ctx.save_text("physical_incident_register.csv", csv_text)
        observed = [r for r in rows if r["status"] in ("pass", "fail")]
        failed = [r for r in rows if r["status"] == "fail"]
        ctx.add(Result(
            "PHY-05", "Physical incident documentation template",
            "fail" if failed else ("pass" if observed else "info"),
            severity="medium" if failed else "info",
            description=(f"Wrote a real incident form (markdown) and a register skeleton (CSV) to evidence for site "
                         f"'{site}'. Documentation controls evaluated from observations: {len(observed)} of "
                         f"{len(items)} ({len(failed)} failing). The template itself is a tool, not a finding."),
            asset=site, source="local",
            cwe=["CWE-778"] if failed else [],
            remediation=("Complete ID-01/ID-02 with a recent closed incident and a dated exercise record."
                         if failed else
                         "Use the generated form for every physical incident; it captures the fields needed to "
                         "close the loop between observation and evidence."),
            evidence=[md_art, csv_art,
                      {"type": "other", "summary": "documentation controls", "items": rows}],
            data={"form": md_art["path"], "register": csv_art["path"], "site": site,
                  "generated_at": now, "items": rows,
                  "mandatory_fields": ["incident_id", "detected_at", "detected_by", "location",
                                       "category", "control_ids", "description", "containment",
                                       "evidence_refs", "root_cause", "corrective_action",
                                       "closed_at", "closed_by"]}))

    # ------------------------------------------------------------ PHY-06 ----
    def aggregate_score(self, ctx: Context) -> None:
        all_rows = [self._evaluate(i) for i in self._checklist]
        applicable = [r for r in all_rows if r.get("answer") != "na"]
        observed = [r for r in applicable if r["status"] in ("pass", "fail")]
        passed = [r for r in observed if r["status"] == "pass"]
        failed = [r for r in observed if r["status"] == "fail"]
        unobserved = [r for r in applicable if r["status"] not in ("pass", "fail")]
        invalid = [r for r in all_rows if r["status"] == "error"]

        completeness = (len(observed) / len(applicable) * 100) if applicable else 0.0
        score = (100.0 * len(passed) / len(observed)) if observed else None
        by_domain: dict[str, dict[str, Any]] = {}
        for r in applicable:
            d = by_domain.setdefault(r["domain"], {"applicable": 0, "observed": 0, "passed": 0, "failed": 0})
            d["applicable"] += 1
            if r["status"] in ("pass", "fail"):
                d["observed"] += 1
                if r["status"] == "pass":
                    d["passed"] += 1
                else:
                    d["failed"] += 1
        for d in by_domain.values():
            d["score"] = round(100.0 * d["passed"] / d["observed"], 1) if d["observed"] else None

        incomplete = bool(unobserved) or completeness < 100.0
        formula = ("score = 100 * (passed controls) / (observed controls), where a control counts as observed "
                   "only when the operator supplied answer=pass|fail; answer=na is excluded from both numerator "
                   "and denominator; unobserved controls are excluded from the score and reported as a "
                   "completeness gap. completeness = observed / applicable * 100.")
        desc = (f"Observed-only physical risk score: {('%.1f' % score) if score is not None else 'n/a'}/100 "
                f"across {len(observed)} observed of {len(applicable)} applicable control(s); "
                f"completeness {completeness:.1f}%.")
        if unobserved:
            desc += (f" Assessment is INCOMPLETE: {len(unobserved)} control(s) not observed "
                     f"({', '.join(r['id'] for r in unobserved[:12])}"
                     f"{', ...' if len(unobserved) > 12 else ''}) - requires on-site operator input.")
        else:
            desc += " All applicable controls were observed."
        if score is None:
            desc += " No control has been observed, so no score can be computed."
        if invalid:
            desc += f" {len(invalid)} observation(s) had an invalid answer and were excluded."

        art = ctx.save_text("physical_risk_summary.csv", score_csv(all_rows, score, completeness))
        ctx.add(Result("PHY-06", "Aggregate physical risk score",
                       "info" if score is None else ("fail" if failed else "pass"),
                       severity=("high" if len(failed) >= 5 else "medium" if failed else "info"),
                       description=desc, asset=ctx.params.get("site_name")
                       or (ctx.targets[0] if ctx.targets else "site"),
                       source="local" if observed else "unavailable",
                       cvss_score=round(score / 10.0, 1) if (score is not None and failed) else None,
                       cwe=["CWE-1263"] if failed else [],
                       remediation=("Close the failing controls and collect the unobserved ones before treating "
                                    "the site as assessed.") if failed else
                                   "Complete the unobserved controls to obtain a full-coverage score.",
                       evidence=[art,
                                 {"type": "other", "summary": "scoring detail",
                                  "formula": formula, "score": score,
                                  "completeness_pct": round(completeness, 2),
                                  "by_domain": by_domain}],
                       data={"score": round(score, 2) if score is not None else None,
                             "formula": formula,
                             "completeness_pct": round(completeness, 2),
                             "incomplete": incomplete,
                             "applicable": len(applicable), "observed": len(observed),
                             "passed": len(passed), "failed_ids": [r["id"] for r in failed],
                             "unobserved_ids": [r["id"] for r in unobserved],
                             "na_ids": [r["id"] for r in applicable if r.get("answer") == "na"],
                             "by_domain": by_domain, "items": all_rows,
                             "checklist_version": self._checklist_meta.get("version"),
                             "checklist_source": self._checklist_meta.get("source"),
                             "observation_errors": self._obs_errors,
                             "summary_csv": art["path"]}))


# ---------------------------------------------------------------- loading --
def load_checklist(ctx: Context) -> tuple[list[dict], dict]:
    path = ctx.params.get("checklist_path")
    meta = {"source": "in-code default", "path": None, "version": DEFAULT_CHECKLIST_VERSION,
            "count": len(DEFAULT_CHECKLIST)}
    if not path:
        return [dict(i) for i in DEFAULT_CHECKLIST], meta
    if not os.path.exists(str(path)):
        meta["error"] = f"params.checklist_path not found: {path} - used the in-code default checklist"
        ctx.add(unavailable("PHY-00", "Custom checklist loading",
                            meta["error"], asset=str(path)))
        return [dict(i) for i in DEFAULT_CHECKLIST], meta
    try:
        text = open(str(path), encoding="utf-8").read()
        if str(path).lower().endswith(".json"):
            doc = json.loads(text)
        else:
            try:
                import yaml
                doc = yaml.safe_load(text)
            except ImportError:
                doc = json.loads(text)
    except Exception as exc:
        meta["error"] = f"checklist could not be parsed ({type(exc).__name__}: {exc}) - used the in-code default"
        return [dict(i) for i in DEFAULT_CHECKLIST], meta
    items = doc.get("items") if isinstance(doc, dict) else doc
    if not isinstance(items, list) or not items:
        meta["error"] = "checklist contained no items - used the in-code default"
        return [dict(i) for i in DEFAULT_CHECKLIST], meta
    normalised = []
    for i, raw in enumerate(items):
        if not isinstance(raw, dict):
            continue
        normalised.append({
            "id": str(raw.get("id") or f"X-{i + 1:02d}"),
            "domain": str(raw.get("domain") or "access_control"),
            "control": str(raw.get("control") or ""),
            "question": str(raw.get("question") or ""),
            "expected_evidence": str(raw.get("expected_evidence") or ""),
        })
    meta.update({"source": "supplied file", "path": str(path), "count": len(normalised),
                 "version": str((doc.get("version") if isinstance(doc, dict) else "") or "unversioned")})
    return normalised or [dict(i) for i in DEFAULT_CHECKLIST], meta


def load_observations(raw: Any) -> tuple[dict[str, dict], list[str]]:
    errors: list[str] = []
    if raw is None:
        return {}, errors
    if isinstance(raw, str):
        if raw.strip().startswith(("{", "[")):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError as exc:
                return {}, [f"observations string was not valid JSON: {exc}"]
        elif os.path.exists(raw):
            try:
                text = open(raw, encoding="utf-8").read()
                try:
                    raw = json.loads(text)
                except json.JSONDecodeError:
                    import yaml
                    raw = yaml.safe_load(text)
            except Exception as exc:
                return {}, [f"observations file could not be read: {exc}"]
        else:
            return {}, [f"observations string was neither JSON nor an existing path: {raw[:60]}"]
    if not isinstance(raw, dict):
        return {}, [f"observations must be a mapping of checklist_id -> object, got {type(raw).__name__}"]
    out: dict[str, dict] = {}
    for k, v in raw.items():
        if not isinstance(v, dict):
            errors.append(f"{k}: observation is not an object (got {type(v).__name__})")
            # Keep it so the checklist item is reported as an observation error
            # rather than silently degrading to "not observed".
            out[str(k)] = {"answer": "", "note": f"malformed observation ({type(v).__name__})",
                           "_malformed": True}
            continue
        ans = str(v.get("answer", "")).strip().lower()
        if ans not in VALID_ANSWERS:
            errors.append(f"{k}: answer {v.get('answer')!r} is not one of pass|fail|na")
        out[str(k)] = {**v, "answer": ans}
    return out, errors


# --------------------------------------------------------------- artefacts --
def incident_form_markdown(site: str, generated: str, meta: dict) -> str:
    return f"""# Physical Security Incident Report

- **Site:** {site}
- **Form version:** {meta.get('version')} (checklist source: {meta.get('source')})
- **Form generated:** {generated}

Complete every field. An incident is only closed when `evidence_refs` lists at least one
retained artefact (photo, access-log export, CCTV clip id) and `closed_by` is signed.

## 1. Identification

| Field | Value |
|---|---|
| Incident ID | PHYS-YYYY-NNN |
| Detected at (UTC) | |
| Detected by (name / role) | |
| Location (building / floor / room) | |
| Location type | perimeter / office / server-room / comms-cabinet / car-park |
| Category | intrusion / tailgating / tamper / theft / CCTV-failure / protest / other |
| Related checklist controls | e.g. AC-02, TE-01 |

## 2. Description

What was observed, in factual terms (no conclusions):

```
```

## 3. Immediate containment

| Action | Owner | Time (UTC) |
|---|---|---|
| | | |

## 4. Evidence retained

| Evidence type | Reference / path | Retained by |
|---|---|---|
| Photo | | |
| CCTV clip | | |
| Access-control log export | | |
| Witness statement | | |

## 5. Investigation

- Root cause:
- Control that failed (checklist id):
- Was the control previously recorded as pass?  yes / no / unknown

## 6. Corrective action

| Action | Owner | Due (UTC) | Verified by |
|---|---|---|---|
| | | | |

## 7. Closure

| Field | Value |
|---|---|
| Closed at (UTC) | |
| Closed by (name / role) | |
| Re-test performed | yes / no |
| Register updated | yes / no |

## 8. Sign-off

- Assessor: ______________________  Date: __________
- Site security owner: ____________  Date: __________
"""


def incident_form_csv(site: str, generated: str) -> str:
    cols = ["incident_id", "site", "detected_at", "detected_by", "location", "location_type",
            "category", "control_ids", "description", "containment", "evidence_refs",
            "root_cause", "corrective_action", "closed_at", "closed_by", "form_generated"]
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(cols)
    w.writerow(["PHYS-YYYY-NNN", site, "", "", "", "", "", "", "", "", "", "", "", "", "", generated])
    return out.getvalue()


def score_csv(items: list[dict], score: float | None, completeness: float) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["checklist_id", "domain", "control", "answer", "status", "note", "evidence_ref"])
    for r in items:
        w.writerow([r["id"], r.get("domain", ""), r.get("control", ""), r.get("answer") or "",
                    r.get("status", ""), (r.get("note") or "")[:200], r.get("evidence_ref") or ""])
    w.writerow([])
    w.writerow(["aggregate_score", "" if score is None else round(score, 2)])
    w.writerow(["completeness_pct", round(completeness, 2)])
    return out.getvalue()
