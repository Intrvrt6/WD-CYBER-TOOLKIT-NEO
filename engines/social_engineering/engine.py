"""Module G - Social Engineering.

Real work only and DNS is the evidence source: SPF/DMARC/DKIM/MX records are
fetched with `dig` and parsed, lookalike domains are generated and actually
resolved, and every "record absent" statement is the observed result of a real
query (nothing is inferred from a template).

Template checks (SOC-03/04) render real HTML fixtures to the evidence
directory.  They are awareness-training artefacts for authorized campaigns
only: the rendered files carry an explicit authorization banner and the landing
page collects nothing by design.
"""
from __future__ import annotations

import concurrent.futures
import csv
import io
import os
import re
import string
from typing import Any

from backend import runner
from engines.base import Context, Result, have, unavailable

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail", "k1", "s1", "dkim"]
LOOKALIKE_TLDS = ["net", "org", "info", "co", "biz", "online"]
HOMOGLYPHS = {"o": "0", "i": "1", "l": "1", "e": "3", "a": "4", "s": "5"}
MAX_LOOKALIKE_PROBES = 40

# Scoring rubric used by SOC-02 (documented in the result so the number is auditable).
RUBRIC = {
    "spf_strict_all": 30, "spf_softfail_all": 18, "spf_neutral_all": 8, "spf_pass_all": 0, "spf_absent": 0,
    "dmarc_reject": 35, "dmarc_quarantine": 22, "dmarc_none": 10, "dmarc_absent": 0, "dmarc_rua_bonus": 0,
    "dkim_valid": 25, "dkim_empty_key": 8, "dkim_absent": 0,
    "mx_present": 10, "mx_null": 10, "mx_absent": 0,
}
GRADES = [(90, "A"), (80, "B"), (65, "C"), (50, "D"), (0, "F")]


class SocialEngine:
    module = "social_engineering"
    title = "Module G - Social Engineering"
    description = ("Email authentication reality check from live DNS (SPF/DMARC/DKIM/MX), lookalike-domain "
                   "resolution, authorization-scoped awareness template rendering, campaign metrics.")
    checks = [
        ("SOC-01", "Email authentication assessment (SPF / DMARC / DKIM / MX)", True),
        ("SOC-02", "Email security scoring", True),
        ("SOC-03", "Phishing awareness template rendering (authorized campaigns)", True),
        ("SOC-04", "Landing-page template generation (non-collecting)", True),
        ("SOC-05", "Awareness reporting metrics", True),
        ("SOC-06", "Impersonation / lookalike domain detection", True),
    ]

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        self._domains = [d for d in (normalise_domain(t) for t in ctx.targets) if d]
        self._email: dict[str, Any] = {}
        self._source = "lab" if ctx.mode == "lab" else "live"
        steps = [("SOC-01", self.email_auth), ("SOC-02", self.scoring),
                 ("SOC-03", self.phishing_templates), ("SOC-04", self.landing_page),
                 ("SOC-05", self.awareness_metrics), ("SOC-06", self.impersonation)]
        for i, (cid, fn) in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("SOC-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining social-engineering checks were not executed.", source="local"))
                break
            try:
                fn(ctx)
            except Exception as exc:
                ctx.add(Result(f"{cid}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    # ------------------------------------------------------------ SOC-01 ----
    def email_auth(self, ctx: Context) -> None:
        if not self._domains:
            ctx.add(unavailable("SOC-01", "Email authentication assessment",
                                "No domain target supplied (targets must contain a DNS name such as example.com)."))
            return
        if not have("dig"):
            ctx.add(unavailable("SOC-01", "Email authentication assessment",
                                "`dig` is not installed on this host, so no DNS record can be fetched. "
                                "Install bind9-dnsutils (or run on a host that has dig) to enable this check."))
            return
        for domain in self._domains:
            entry: dict[str, Any] = {"domain": domain, "queries": []}

            # --- SPF ---------------------------------------------------------
            spf_records, e = dig_txt(domain)
            entry["queries"].append(e)
            spf = next((r for r in spf_records if r.lower().startswith("v=spf1")), None)
            spf_parsed = parse_spf(spf) if spf else None
            entry["spf"] = {"record": spf, "all_txt_records": spf_records, "parsed": spf_parsed}

            # --- DMARC -------------------------------------------------------
            dmarc_records, e = dig_txt(f"_dmarc.{domain}")
            entry["queries"].append(e)
            dmarc = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)
            entry["dmarc"] = {"record": dmarc, "all_txt_records": dmarc_records,
                              "parsed": parse_dmarc(dmarc) if dmarc else None}

            # --- DKIM selector probes ---------------------------------------
            dkim: dict[str, Any] = {}
            for sel in DKIM_SELECTORS:
                name = f"{sel}._domainkey.{domain}"
                recs, e = dig_txt(name)
                entry["queries"].append(e)
                rec = next((r for r in recs if "v=dkim1" in r.lower() or "p=" in r.lower()), None)
                key = None
                if rec:
                    m = re.search(r"\bp\s*=\s*([A-Za-z0-9+/=]*)", rec)
                    key = m.group(1) if m else None
                dkim[sel] = {"name": name, "record": rec, "key_b64_len": len(key or ""),
                             "key_present": bool(key), "key_bits_estimate": estimate_key_bits(key)}
            entry["dkim"] = dkim
            entry["dkim_found"] = [s for s, v in dkim.items() if v["record"]]
            entry["dkim_valid"] = [s for s, v in dkim.items() if v["key_present"]]
            # Control probe: a random selector that cannot exist.  If it returns the
            # same record, the zone serves a wildcard placeholder and the selector
            # hits above must NOT be read as real published keys.
            control_name = f"{random_selector()}._domainkey.{domain}"
            control_recs, e = dig_txt(control_name)
            entry["queries"].append(e)
            control_rec = next((r for r in control_recs if "v=dkim1" in r.lower() or "p=" in r.lower()), None)
            found_records = {v["record"] for v in dkim.values() if v["record"]}
            entry["dkim_control"] = {"name": control_name, "record": control_rec,
                                     "wildcard_placeholder": bool(control_rec) and found_records == {control_rec}}
            entry["dkim_real_keys"] = [s for s, v in dkim.items() if v["key_present"]]
            if entry["dkim_control"]["wildcard_placeholder"]:
                entry["dkim_found"] = []
                entry["dkim_valid"] = []
                entry["dkim_wildcard"] = True

            # --- MX ----------------------------------------------------------
            mx, e = dig_generic("MX", domain)
            entry["queries"].append(e)
            entry["mx"] = {"records": mx, "null_mx": any(rw.strip().endswith(" .") or rw.strip() == "0 ." for rw in mx)}
            self._email[domain] = entry

            found = (f"SPF={'present' if spf else 'absent'}, "
                     f"DMARC={'present' if dmarc else 'absent'}, "
                     f"DKIM selectors with a record={entry['dkim_found'] or 'none'}, "
                     f"MX={'present' if mx else 'absent'}")
            ctx.add(Result("SOC-01", f"Email authentication records for {domain}", "info",
                           description=(f"Live DNS lookups for {domain}: {found}. "
                                        f"SPF mechanisms={len((spf_parsed or {}).get('mechanisms', []))}, "
                                        f"all-qualifier={(spf_parsed or {}).get('all') or 'none'}."),
                           asset=domain, source="live",
                           evidence=[{"type": "command_output", "summary": q["command"], "stdout": q["stdout"][:2000]}
                                     for q in entry["queries"] if q.get("command")][:6],
                           data=entry))

            # --- individual observations ------------------------------------
            if not spf:
                ctx.add(Result("SOC-01b", "No SPF record observed", "fail", severity="medium",
                               description=(f"A TXT query for {domain} returned {spf_records or 'no TXT records'}; "
                                            f"no record starting with v=spf1 was present."),
                               asset=domain, source="live", cvss_score=5.3, cwe=["CWE-290"],
                               remediation="Publish an SPF record listing only authorized senders and ending in -all.",
                               evidence=[{"type": "command_output", "command": f"dig +short TXT {domain}",
                                          "stdout": "\n".join(spf_records) or "(no output)"}],
                               data={"txt_records": spf_records}))
            elif spf_parsed and spf_parsed.get("all") in ("+all", "?all", None):
                ctx.add(Result("SOC-01c", "SPF policy does not restrict senders", "fail", severity="medium",
                               description=(f"{domain} publishes '{spf}' whose all-mechanism is "
                                            f"'{spf_parsed.get('all') or 'absent'}' - this authorizes (or fails to "
                                            f"deny) unauthorized senders rather than rejecting them."),
                               asset=domain, source="live", cvss_score=5.3, cwe=["CWE-290"],
                               remediation="End the SPF record with -all (hard fail) once all legitimate senders are listed.",
                               evidence=[{"type": "command_output", "command": f"dig +short TXT {domain}",
                                          "stdout": spf}],
                               data={"spf": spf, "parsed": spf_parsed}))
            if not dmarc:
                ctx.add(Result("SOC-01d", "No DMARC record observed", "fail", severity="medium",
                               description=(f"A TXT query for _dmarc.{domain} returned "
                                            f"{dmarc_records or 'no TXT records'}; no v=DMARC1 policy was present, so "
                                            f"receivers have no instruction for failing mail."),
                               asset=domain, source="live", cvss_score=5.3, cwe=["CWE-290"],
                               remediation="Publish _dmarc.<domain> TXT 'v=DMARC1; p=reject; rua=mailto:...' after "
                                           "monitoring with p=none.",
                               evidence=[{"type": "command_output", "command": f"dig +short TXT _dmarc.{domain}",
                                          "stdout": "\n".join(dmarc_records) or "(no output)"}],
                               data={"txt_records": dmarc_records}))
            elif (entry["dmarc"].get("parsed") or {}).get("p") == "none":
                ctx.add(Result("SOC-01e", "DMARC policy is monitor-only", "fail", severity="low",
                               description=(f"{domain} publishes p=none ('{dmarc}'), so failing mail is reported but "
                                            f"not quarantined or rejected."),
                               asset=domain, source="live", cvss_score=3.7, cwe=["CWE-290"],
                               remediation="Move to p=quarantine then p=reject once alignment is verified.",
                               evidence=[{"type": "command_output", "command": f"dig +short TXT _dmarc.{domain}",
                                          "stdout": dmarc}],
                               data={"dmarc": entry["dmarc"].get("parsed")}))
            if entry.get("dkim_wildcard"):
                ctx.add(Result("SOC-01g", "DKIM selector probes answered by a wildcard placeholder", "info",
                               severity="low",
                               description=(f"Every probed selector at <selector>._domainkey.{domain} returned the same "
                                            f"record '{control_rec}', and the control probe {control_name} (a random "
                                            f"selector that cannot exist) returned it too, so the zone serves a "
                                            f"wildcard placeholder. Per RFC 6376 an empty p= means no key, so no usable "
                                            f"DKIM key was observed; the selector hits are not real published keys."),
                               asset=domain, source="live", cwe=["CWE-290"],
                               remediation="Publish a real selector with a 2048-bit p= key, and remove the wildcard "
                                           "placeholder so probes are unambiguous.",
                               evidence=[{"type": "other", "summary": "control probe",
                                          "control": entry["dkim_control"],
                                          "selectors": {k: v["record"] for k, v in dkim.items()}}],
                               data={"control": entry["dkim_control"],
                                     "selectors": {k: v["record"] for k, v in dkim.items()}}))
            elif not entry["dkim_valid"]:
                rev = [s for s, v in dkim.items() if v["record"] and not v["key_present"]]
                ctx.add(Result("SOC-01f", "No usable DKIM key observed on common selectors", "info",
                               severity="low",
                               description=(f"Probed selectors {', '.join(DKIM_SELECTORS)} at <selector>._domainkey.{domain}. "
                                            f"Selectors returning a record: {entry['dkim_found'] or 'none'}"
                                            + (f" (revoked/empty p= on {rev})" if rev else "") +
                                            ". Zero usable keys does not prove DKIM is absent - the selector may be "
                                            "non-standard or the key may be published on a subdomain."),
                               asset=domain, source="live", cwe=["CWE-290"],
                               remediation="Confirm the live selector with the mail provider and publish a 2048-bit key.",
                               evidence=[{"type": "other", "summary": "selector probe results", "dkim": dkim}],
                               data={"selectors": {k: {"record": v["record"], "key_present": v["key_present"]}
                                                   for k, v in dkim.items()},
                                     "revoked": rev}))

    # ------------------------------------------------------------ SOC-02 ----
    def scoring(self, ctx: Context) -> None:
        if not self._email:
            ctx.add(unavailable("SOC-02", "Email security scoring",
                                "No email-authentication data was collected (see SOC-01), so no score can be computed."))
            return
        rows = []
        for domain, e in self._email.items():
            parts: list[dict] = []
            spf = e.get("spf") or {}
            parsed = spf.get("parsed") or {}
            all_mech = (parsed.get("all") or "").lower()
            if not spf.get("record"):
                spf_pts, spf_reason = RUBRIC["spf_absent"], "no SPF record observed"
            elif all_mech == "-all":
                spf_pts, spf_reason = RUBRIC["spf_strict_all"], "SPF ends with -all (hard fail)"
            elif all_mech == "~all":
                spf_pts, spf_reason = RUBRIC["spf_softfail_all"], "SPF ends with ~all (soft fail)"
            elif all_mech == "?all":
                spf_pts, spf_reason = RUBRIC["spf_neutral_all"], "SPF ends with ?all (neutral)"
            else:
                spf_pts, spf_reason = RUBRIC["spf_pass_all"], f"SPF ends with {all_mech or '+all/no all'}"
            parts.append({"control": "SPF", "points": spf_pts, "max": 30, "reason": spf_reason})

            dm = (e.get("dmarc") or {}).get("parsed") or {}
            if not (e.get("dmarc") or {}).get("record"):
                dm_pts, dm_reason = RUBRIC["dmarc_absent"], "no DMARC record observed"
            elif dm.get("p") == "reject":
                dm_pts, dm_reason = RUBRIC["dmarc_reject"], "p=reject"
            elif dm.get("p") == "quarantine":
                dm_pts, dm_reason = RUBRIC["dmarc_quarantine"], "p=quarantine"
            else:
                dm_pts, dm_reason = RUBRIC["dmarc_none"], f"p={dm.get('p') or 'none'}"
            parts.append({"control": "DMARC", "points": dm_pts, "max": 35, "reason": dm_reason})

            if e.get("dkim_valid"):
                dk_pts = RUBRIC["dkim_valid"]
                dk_reason = "usable key on selector(s) " + ", ".join(e["dkim_valid"])
            elif e.get("dkim_wildcard"):
                dk_pts = RUBRIC["dkim_absent"]
                dk_reason = "selector probes hit a wildcard placeholder with an empty p= (no key published)"
            elif e.get("dkim_found"):
                dk_pts = RUBRIC["dkim_empty_key"]
                dk_reason = "record present but p= is empty (key revoked): " + ", ".join(e["dkim_found"])
            else:
                dk_pts, dk_reason = RUBRIC["dkim_absent"], "no key on the common selectors probed"
            parts.append({"control": "DKIM", "points": dk_pts, "max": 25, "reason": dk_reason})

            mx = (e.get("mx") or {})
            if mx.get("records"):
                mx_pts = RUBRIC["mx_null"] if mx.get("null_mx") else RUBRIC["mx_present"]
                mx_reason = "null MX (explicit no-mail domain)" if mx.get("null_mx") else "MX present"
            else:
                mx_pts, mx_reason = RUBRIC["mx_absent"], "no MX record observed"
            parts.append({"control": "MX", "points": mx_pts, "max": 10, "reason": mx_reason})

            score = sum(p["points"] for p in parts)
            grade = next(g for threshold, g in GRADES if score >= threshold)
            rows.append({"domain": domain, "score": score, "grade": grade, "components": parts})

        worst = min(rows, key=lambda r: r["score"])
        ctx.add(Result("SOC-02", "Email security scoring", "info",
                       description=(f"Scored {len(rows)} domain(s) with the stated rubric: "
                                    + "; ".join(f"{r['domain']}={r['score']}/100 (grade {r['grade']})" for r in rows)
                                    + f". Weakest: {worst['domain']}."),
                       asset=",".join(r["domain"] for r in rows), source="live",
                       evidence=[{"type": "other", "summary": "score breakdown", "scores": rows}],
                       data={"scores": rows, "rubric": RUBRIC,
                             "grade_bands": {g: t for t, g in GRADES}}))
        if worst["score"] < 65:
            ctx.add(Result("SOC-02b", "Email authentication posture below protective baseline", "fail",
                           severity="medium" if worst["score"] >= 50 else "high",
                           description=(f"{worst['domain']} scores {worst['score']}/100 (grade {worst['grade']}). "
                                        f"Failing components: "
                                        + ", ".join(f"{p['control']} {p['points']}/{p['max']} ({p['reason']})"
                                                    for p in worst["components"] if p["points"] < p["max"])),
                           asset=worst["domain"], source="live",
                           cvss_score=6.5 if worst["score"] >= 50 else 7.5, cwe=["CWE-290"],
                           remediation="Close the failing components (publish -all SPF, p=reject DMARC, a live DKIM key).",
                           evidence=[{"type": "other", "summary": "weakest domain", "score": worst}],
                           data=worst))

    # ------------------------------------------------------------ SOC-03 ----
    def phishing_templates(self, ctx: Context) -> None:
        params = ctx.params
        fields = {
            "organization": params.get("organization", "Example Corporation"),
            "sender_name": params.get("sender_name", "IT Service Desk"),
            "sender_role": params.get("sender_role", "Security Operations"),
            "target_name": params.get("target_name", "A. Employee"),
            "target_department": params.get("target_department", "Finance"),
            "cta_url": params.get("cta_url", "https://training.example.invalid/awareness/step-1"),
            "deadline": params.get("deadline", "in 24 hours"),
            "reference_id": params.get("reference_id", "AWR-2024-0042"),
            "report_channel": params.get("report_channel", "phishing@example.com"),
            "authorization_ref": params.get("authorization_ref", "NOT SUPPLIED - provide params.authorization_ref"),
        }
        rendered: list[dict] = []
        for name, template in (("awareness_policy_notice.html", TEMPLATE_POLICY),
                               ("awareness_document_review.html", TEMPLATE_DOCUMENT)):
            html = string.Template(template).substitute(fields)
            art = ctx.save_text(name, html)
            rendered.append(art)
        ctx.add(Result(
            "SOC-03", "Phishing awareness template rendering (authorized campaigns)", "info",
            description=(f"Rendered {len(rendered)} HTML awareness templates with {len(fields)} substituted fields "
                         f"and saved them as evidence. These are AUTHORIZED-campaign artefacts only: the rendered "
                         f"files carry an authorization banner and must not be delivered outside a written engagement "
                         f"(authorization reference: {fields['authorization_ref']})."),
            asset=fields["organization"], source="lab",
            evidence=rendered + [{"type": "other", "summary": "substituted fields", "fields": fields}],
            data={"artifacts": [a["path"] for a in rendered], "fields": fields,
                  "note": "authorized awareness testing only"}))
        if "NOT SUPPLIED" in fields["authorization_ref"]:
            ctx.add(Result("SOC-03b", "Campaign authorization reference not supplied", "info", severity="low",
                           description=("params.authorization_ref was not provided, so the rendered templates state "
                                        "that no authorization reference exists. Supply the engagement reference before "
                                        "using these artefacts in any campaign."),
                           asset=fields["organization"], source="lab",
                           remediation="Pass params.authorization_ref with the signed engagement identifier.",
                           data={"authorization_ref": fields["authorization_ref"]}))

    # ------------------------------------------------------------ SOC-04 ----
    def landing_page(self, ctx: Context) -> None:
        fields = {
            "organization": ctx.params.get("organization", "Example Corporation"),
            "program_name": ctx.params.get("program_name", "Security Awareness Programme"),
            "report_channel": ctx.params.get("report_channel", "phishing@example.com"),
            "authorization_ref": ctx.params.get("authorization_ref", "NOT SUPPLIED"),
            "deadline": ctx.params.get("deadline", "in 24 hours"),
        }
        html = string.Template(TEMPLATE_LANDING).substitute(fields)
        art = ctx.save_text("awareness_landing_page.html", html)
        ctx.add(Result(
            "SOC-04", "Landing-page template generation (non-collecting)", "info",
            description=("Generated a real HTML landing page fixture and saved it to evidence. It contains no form "
                         "action, no network call and no storage: the submit handler is cancelled in-page, so it "
                         "collects nothing by default. It teaches the 'pause and verify' message and points at the "
                         "internal reporting channel."),
            asset=fields["organization"], source="lab",
            evidence=[art, {"type": "other", "summary": "non-collection design",
                            "notes": ["form has no action attribute and no method",
                                      "onsubmit returns false (no request is made)",
                                      "no cookies, no localStorage, no analytics"]}],
            data={"artifact": art["path"], "collects_data": False, "fields": fields}))

    # ------------------------------------------------------------ SOC-05 ----
    def awareness_metrics(self, ctx: Context) -> None:
        path = ctx.params.get("campaign_results_csv")
        schema = ["recipient_id", "department", "sent_at", "opened_at", "clicked_at",
                  "submitted_at", "reported_at"]
        if not path:
            sample = ("recipient_id,department,sent_at,opened_at,clicked_at,submitted_at,reported_at\n"
                      "SAMPLE-001,Finance,2024-05-01T09:00:00Z,2024-05-01T09:14:00Z,2024-05-01T09:15:00Z,"
                      "2024-05-01T09:16:00Z,\n"
                      "SAMPLE-002,Engineering,2024-05-01T09:00:00Z,2024-05-01T09:31:00Z,,,2024-05-01T09:40:00Z\n")
            art = ctx.save_text("awareness_metrics_schema.csv", sample)
            ctx.add(Result(
                "SOC-05", "Awareness reporting metrics", "info",
                description=("No params.campaign_results_csv supplied, so no real campaign metrics exist to compute. "
                             "Emitted the metrics schema and ONE worked example clearly labelled SAMPLE "
                             "(not real results)."),
                asset="schema-only", source="lab",
                evidence=[art, {"type": "other", "summary": "expected columns", "schema": schema}],
                data={"schema": schema, "sample_only": True,
                      "metric_definitions": {
                          "open_rate": "rows with opened_at / rows sent",
                          "click_rate": "rows with clicked_at / rows sent",
                          "submit_rate": "rows with submitted_at / rows sent",
                          "report_rate": "rows with reported_at / rows sent",
                          "click_to_report": "reported_at rows / clicked_at rows"}}))
            return
        if not os.path.exists(str(path)):
            ctx.add(unavailable("SOC-05", "Awareness reporting metrics",
                                f"params.campaign_results_csv does not exist: {path}", asset=str(path)))
            return
        try:
            with open(str(path), encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
        except (OSError, csv.Error) as exc:
            ctx.add(unavailable("SOC-05", "Awareness reporting metrics",
                                f"{os.path.basename(str(path))} could not be parsed as CSV: {exc}",
                                asset=os.path.basename(str(path))))
            return
        total = len(rows) or 1
        counts = {k: sum(1 for r in rows if (r.get(k) or "").strip()) for k in
                  ("sent_at", "opened_at", "clicked_at", "submitted_at", "reported_at")}
        names = {"sent_at": "sent", "opened_at": "open", "clicked_at": "click",
                 "submitted_at": "submit", "reported_at": "report"}
        metrics = {f"{names[k]}_rate": round(counts[k] / total, 4) for k in counts}
        metrics["click_to_report_rate"] = (round(counts["reported_at"] / counts["clicked_at"], 4)
                                           if counts["clicked_at"] else None)
        by_dept: dict[str, dict[str, int]] = {}
        for r in rows:
            dept = (r.get("department") or "unspecified").strip() or "unspecified"
            d = by_dept.setdefault(dept, {"recipients": 0, "clicked": 0, "reported": 0})
            d["recipients"] += 1
            d["clicked"] += 1 if (r.get("clicked_at") or "").strip() else 0
            d["reported"] += 1 if (r.get("reported_at") or "").strip() else 0
        out_csv = io.StringIO()
        w = csv.writer(out_csv)
        w.writerow(["metric", "value"])
        w.writerow(["recipients", len(rows)])
        for k, v in metrics.items():
            w.writerow([k, "" if v is None else v])
        w.writerow([])
        w.writerow(["department", "recipients", "clicked", "reported"])
        for dept, d in sorted(by_dept.items()):
            w.writerow([dept, d["recipients"], d["clicked"], d["reported"]])
        art = ctx.save_text("awareness_metrics.csv", out_csv.getvalue())
        ctx.add(Result(
            "SOC-05", "Awareness reporting metrics", "info",
            description=(f"Computed real metrics from {os.path.basename(str(path))}: {len(rows)} recipient row(s); "
                         f"open_rate={fmt_rate(metrics['open_rate'])}, click_rate={fmt_rate(metrics['click_rate'])}, "
                         f"submit_rate={fmt_rate(metrics['submit_rate'])}, report_rate={fmt_rate(metrics['report_rate'])}."),
            asset=os.path.basename(str(path)), source="live",
            evidence=[art, {"type": "file", "path": str(path), "summary": "campaign results input"}],
            data={"recipients": len(rows), "counts": counts, "metrics": metrics,
                  "by_department": by_dept, "output": art["path"]}))

    # ------------------------------------------------------------ SOC-06 ----
    def impersonation(self, ctx: Context) -> None:
        if not self._domains:
            ctx.add(unavailable("SOC-06", "Impersonation / lookalike domain detection",
                                "No domain target supplied to derive lookalike permutations from."))
            return
        if not have("dig"):
            ctx.add(unavailable("SOC-06", "Impersonation / lookalike domain detection",
                                "`dig` is not installed, so generated lookalike domains cannot be resolved."))
            return
        for domain in self._domains:
            candidates = generate_lookalikes(domain)[:MAX_LOOKALIKE_PROBES]
            resolved: list[dict] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(resolve_name, c["domain"]): c for c in candidates}
                for fut in concurrent.futures.as_completed(futures):
                    c = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as exc:  # pragma: no cover
                        res = {"addresses": [], "mx": [], "error": f"{type(exc).__name__}: {exc}"}
                    c.update(res)
                    c["mx_present"] = bool(res.get("mx"))
            for c in candidates:
                if c.get("addresses"):
                    c["has_mx"] = bool(c.get("mx"))
                    resolved.append(c)
            resolved.sort(key=lambda c: (not c.get("has_mx"), c["domain"]))
            art = ctx.save_text(f"lookalike_probes_{domain}.json",
                                __import__("json").dumps({"base": domain, "probes": candidates}, indent=2))
            ctx.add(Result(
                "SOC-06", f"Lookalike domain detection for {domain}", "info",
                description=(f"Generated {len(candidates)} stated permutations of {domain} "
                             f"({sorted({c['technique'] for c in candidates})}) and resolved each with dig: "
                             f"{len(resolved)} resolve to an A record"
                             + (f", {sum(1 for c in resolved if c.get('has_mx'))} of those also publish MX"
                                if resolved else "") + ". Registration ownership is NOT verified here."),
                asset=domain, source="live",
                evidence=[art, {"type": "other", "summary": "resolved lookalikes", "resolved": resolved[:20]}],
                data={"base": domain, "probes": len(candidates), "resolved": resolved,
                      "resolved_count": len(resolved),
                      "with_mx": [c["domain"] for c in resolved if c.get("has_mx")],
                      "not_resolved": [c["domain"] for c in candidates if not c.get("addresses")]}))
            if resolved:
                ctx.add(Result("SOC-06b", "Lookalike domains of the assessed brand resolve", "info",
                               severity="low",
                               description=(f"{len(resolved)} permutation(s) of {domain} currently resolve, e.g. "
                                            + ", ".join(f"{c['domain']} ({c['technique']} -> "
                                                        f"{','.join(c['addresses'][:2])}"
                                                        + (", MX" if c.get("has_mx") else "") + ")"
                                                        for c in resolved[:8])
                                            + ". Resolving does not by itself prove malicious intent; each domain "
                                              "needs ownership/WHOIS review and brand monitoring enrollment."),
                               asset=domain, source="live", cwe=["CWE-290"],
                               remediation="Feed these permutations to brand-protection monitoring and consider "
                                           "defensive registration for the highest-risk ones.",
                               evidence=[{"type": "other", "summary": "resolved permutations",
                                          "resolved": resolved[:15]}],
                               data={"resolved": resolved[:25]}))


# ------------------------------------------------------------------ templ --
AUTH_BANNER = """  <div style="background:#7a1f1f;color:#fff;padding:10px 16px;font:600 13px system-ui">
    AUTHORIZED SECURITY AWARENESS TEST - authorization reference: $authorization_ref.
    Do not deliver this artefact outside a written engagement.
  </div>"""

TEMPLATE_POLICY = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Security briefing required - $organization</title></head>
<body style="margin:0;background:#f4f5f7;font:15px/1.5 system-ui,Segoe UI,Arial">
""" + AUTH_BANNER + """
  <div style="max-width:620px;margin:24px auto;background:#fff;border:1px solid #dfe3e8;border-radius:8px">
    <div style="padding:20px 24px;border-bottom:1px solid #eef1f4">
      <strong>$organization - $sender_role</strong>
    </div>
    <div style="padding:24px">
      <p>Hello $target_name,</p>
      <p>Our records show that the mandatory security briefing for <strong>$target_department</strong>
         has not been completed. Access to shared resources may be suspended $deadline.</p>
      <p>Reference: <code>$reference_id</code></p>
      <p><a href="$cta_url" style="display:inline-block;background:#1f4fd8;color:#fff;padding:10px 18px;
         border-radius:6px;text-decoration:none">Open the briefing</a></p>
      <p>If you were not expecting this message, forward it to <a href="mailto:$report_channel">$report_channel</a>
         and do not use the link.</p>
      <p style="color:#667085;font-size:13px">$sender_name - $sender_role, $organization</p>
    </div>
  </div>
</body></html>
"""

TEMPLATE_DOCUMENT = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Document review requested - $organization</title></head>
<body style="margin:0;background:#eef1f5;font:15px/1.5 Georgia,serif">
""" + AUTH_BANNER + """
  <div style="max-width:600px;margin:24px auto;background:#fff;border-radius:6px;padding:24px">
    <p>Dear $target_name,</p>
    <p>A document requiring your review for <strong>$target_department</strong> has been shared with you.</p>
    <table style="border-collapse:collapse;margin:12px 0">
      <tr><td style="padding:4px 12px 4px 0;color:#555">Document</td>
          <td style="padding:4px 0">Q2 review pack - $reference_id.pdf</td></tr>
      <tr><td style="padding:4px 12px 4px 0;color:#555">Deadline</td><td style="padding:4px 0">$deadline</td></tr>
      <tr><td style="padding:4px 12px 4px 0;color:#555">Shared by</td>
          <td style="padding:4px 0">$sender_name, $sender_role</td></tr>
    </table>
    <p><a href="$cta_url">Review the document</a></p>
    <p style="color:#666;font-size:13px">Suspect this message? Report it to
      <a href="mailto:$report_channel">$report_channel</a>.</p>
  </div>
</body></html>
"""

TEMPLATE_LANDING = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title>Security awareness - $program_name</title>
<style>
  body{margin:0;background:#0f172a;color:#e2e8f0;font:16px/1.6 system-ui,Segoe UI,Arial;display:flex;
       min-height:100vh;align-items:center;justify-content:center}
  .card{max-width:620px;background:#1e293b;border:1px solid #334155;border-radius:14px;padding:32px}
  h1{margin:0 0 12px;font-size:22px}
  .badge{display:inline-block;background:#164e63;color:#a5f3fc;border-radius:999px;
         padding:4px 12px;font-size:12px;letter-spacing:.04em;text-transform:uppercase}
  ul{padding-left:20px} code{background:#0b1220;padding:2px 6px;border-radius:4px}
  button{background:#334155;color:#e2e8f0;border:1px solid #475569;border-radius:8px;padding:10px 16px}
</style></head>
<body>
  <main class="card">
    <span class="badge">Awareness training - no data collected</span>
    <h1>That link came from a simulation</h1>
    <p>You just opened a simulated message from the <strong>$program_name</strong> at
       <strong>$organization</strong>. Nothing you did here was recorded: this page has no form action,
       makes no network request and stores nothing.</p>
    <p><strong>What made this message suspicious?</strong></p>
    <ul>
      <li>Unrequested urgency ("$deadline" style deadlines)</li>
      <li>A link whose real destination differs from the display text</li>
      <li>Requests for credentials, payment changes or file downloads</li>
    </ul>
    <p><strong>What to do next:</strong> report suspected messages to
       <code>$report_channel</code> and verify via a channel you already trust
       (phone directory, internal portal) rather than the address in the message.</p>
    <form onsubmit="return false;">
      <button type="submit">Close this page</button>
    </form>
    <p style="color:#94a3b8;font-size:12px">Authorization reference: $authorization_ref.
       This artefact is for authorized awareness programmes only.</p>
  </main>
</body></html>
"""


# ---------------------------------------------------------------- DNS ------
def normalise_domain(target: str) -> str:
    value = (target or "").strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value)
    value = value.split("/", 1)[0].split("@")[-1].split(":")[0]
    if not value or "." not in value or re.fullmatch(r"[\d.]+", value):
        return ""
    if not re.fullmatch(r"[a-z0-9.\-]+", value):
        return ""
    return value


def random_selector() -> str:
    """A selector label that cannot plausibly exist, used as a control probe."""
    import secrets
    return "ctrl" + secrets.token_hex(5)


def dig_txt(name: str) -> tuple[list[str], dict]:
    """Return one TXT record per answer line.

    `dig +short TXT` prints one line per record; a single record longer than
    255 bytes is printed as several quoted chunks on the SAME line, which must
    be concatenated.  Lines are therefore joined within, never across, answers.
    """
    res = runner.run(["dig", "+short", "+time=3", "+tries=1", "TXT", name], timeout=12)
    raw = clean_dig_lines(res.stdout)
    records = [unquote_txt(line) for line in raw]
    records = [r for r in dict.fromkeys(records) if r]
    return records, {"command": f"dig +short TXT {name}", "stdout": (res.stdout or "").strip(),
                     "returncode": res.returncode}


def clean_dig_lines(stdout: str | None) -> list[str]:
    """Keep only real answer lines: +short still echoes ';; communications error'
    and ';; connection timed out' diagnostics to stdout when a resolver fails."""
    out = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        out.append(s)
    return out


def dig_generic(rtype: str, name: str) -> tuple[list[str], dict]:
    res = runner.run(["dig", "+short", "+time=3", "+tries=1", rtype, name], timeout=12)
    vals = clean_dig_lines(res.stdout)
    return vals, {"command": f"dig +short {rtype} {name}", "stdout": (res.stdout or "").strip(),
                  "returncode": res.returncode}


def unquote_txt(value: str) -> str:
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', value or "")
    if parts:
        return "".join(parts).replace('\\"', '"')
    return (value or "").strip()


def parse_spf(record: str) -> dict:
    tokens = (record or "").split()[1:]
    mechanisms, modifiers = [], {}
    for tok in tokens:
        low = tok.lower()
        if "=" in tok and not low.startswith(("ip4:", "ip6:")):
            k, v = tok.split("=", 1)
            modifiers[k.lower()] = v
            continue
        mechanisms.append(tok)
    all_mech = next((m for m in mechanisms if m.lower().lstrip("+-~?") == "all"), None)
    lookups = sum(1 for m in mechanisms
                  if m.lower().lstrip("+-~?").startswith(("include:", "exists:", "a", "mx", "ptr", "redirect")))
    return {"mechanisms": mechanisms, "modifiers": modifiers, "all": all_mech,
            "dns_lookup_mechanisms": lookups,
            "record_length": len(record or ""),
            "multiple_records_warning": False}


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in (record or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return {"tags": tags, "p": tags.get("p"), "sp": tags.get("sp"), "rua": tags.get("rua"),
            "ruf": tags.get("ruf"), "pct": tags.get("pct"), "adkim": tags.get("adkim"),
            "aspf": tags.get("aspf"), "fo": tags.get("fo")}


def estimate_key_bits(b64: str | None) -> int | None:
    """Rough RSA modulus size from the DER length of a base64 SubjectPublicKeyInfo."""
    if not b64:
        return None
    import base64
    try:
        der = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception:
        return None
    # A 2048-bit key yields a ~294-byte SPKI; 1024-bit ~162 bytes.
    if len(der) > 250:
        return 2048
    if len(der) > 100:
        return 1024
    return None


def resolve_name(name: str) -> dict:
    a, _e = dig_generic("A", name)
    mx, _e2 = dig_generic("MX", name)
    return {"addresses": a, "mx": mx}


def fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2%}"


def generate_lookalikes(domain: str) -> list[dict]:
    label, _, tld = domain.partition(".")
    out: list[dict] = []

    def add(name: str, technique: str) -> None:
        if name and name != domain and name not in {c["domain"] for c in out}:
            out.append({"domain": name, "technique": technique})

    for i in range(len(label)):
        add(f"{label[:i]}{label[i+1:]}.{tld}", "character-omission")
    for i in range(len(label) - 1):
        swapped = label[:i] + label[i + 1] + label[i] + label[i + 2:]
        add(f"{swapped}.{tld}", "adjacent-transposition")
    for i, ch in enumerate(label):
        if ch in HOMOGLYPHS:
            add(f"{label[:i]}{HOMOGLYPHS[ch]}{label[i+1:]}.{tld}", "homoglyph-substitution")
    for tld_alt in LOOKALIKE_TLDS:
        add(f"{label}.{tld_alt}", "tld-substitution")
    if len(label) > 4:
        mid = len(label) // 2
        add(f"{label[:mid]}-{label[mid:]}.{tld}", "hyphenation")
        add(f"{label[:mid]}{label[mid:]}-online.{tld}", "keyword-suffix")
    add(f"{label}-secure.{tld}", "keyword-suffix")
    add(f"{label}-login.{tld}", "keyword-suffix")
    add(f"login-{label}.{tld}", "keyword-prefix")
    add(f"{label}{tld}.{tld}", "tld-duplication")
    add(f"{label}{label}.{tld}", "label-duplication")
    return out
