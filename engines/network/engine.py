"""Module A - Network Security.

Real work only: nmap discovery/port scan, DNS resolution and record harvest,
TLS certificate and protocol assessment over the wire, live packet capture and
analysis with tshark/tcpdump when an interface is available, local IP/ARP
inspection for segmentation review.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import time
from typing import Any

from backend import runner
from engines import base
from engines.base import Context, Result, artifact, have, unavailable


class NetworkEngine:
    module = "network"
    title = "Module A - Network Security"
    description = "Discovery, port/service inventory, DNS, TLS posture, capture analysis, segmentation review."
    checks = [
        ("NET-01", "Host discovery", True),
        ("NET-02", "TCP port and service inventory", True),
        ("NET-03", "DNS resolution and record harvest", True),
        ("NET-04", "TLS configuration assessment", True),
        ("NET-05", "Packet capture and protocol analysis", True),
        ("NET-06", "ARP / neighbour anomaly review", True),
        ("NET-07", "Segmentation and exposure review", True),
        ("NET-08", "Intrusion detection integration (Suricata/Zeek)", False),
    ]

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        targets = ctx.targets
        steps = [("NET-01", self.host_discovery), ("NET-02", self.port_scan),
                 ("NET-03", self.dns_checks), ("NET-04", self.tls_checks),
                 ("NET-05", self.capture_analysis), ("NET-06", self.arp_review),
                 ("NET-07", self.segmentation), ("NET-08", self.ids_integration)]
        for i, (_cid, fn) in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("NET-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining network checks were not executed.", source="local"))
                break
            try:
                fn(ctx, targets)
            except Exception as exc:  # keep a failing check from killing the run
                ctx.add(Result(f"{_cid}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    # ---------------------------------------------------------- NET-01 hosts --
    def host_discovery(self, ctx: Context, targets: list[str]) -> None:
        hosts: list[str] = []
        for t in targets:
            tt = base_target(t)
            if is_network(t):
                hosts.extend(base.cidr_hosts(t, limit=256))
            else:
                hosts.append(tt)
        hosts = list(dict.fromkeys(hosts))
        if not hosts:
            ctx.add(unavailable("NET-01", "Host discovery", "No resolvable targets supplied."))
            return

        live: list[str] = []
        evidence: list[dict] = []
        if have("nmap") and len(hosts) <= 256:
            res = runner.run(["nmap", "-sn", "-PE", "-PS22,80,443", "--host-timeout", "25s",
                              "-oG", "-", *hosts], timeout=min(240, 30 + len(hosts)))
            for line in res.stdout.splitlines():
                m = re.match(r"^Host: (\S+) \(([^)]*)\)\s+Status: Up", line)
                if m:
                    live.append(m.group(1))
            evidence.append(res.as_evidence())
            source = "live"
        else:
            for h in hosts:
                if tcp_ping(h, 443, 1.5) or tcp_ping(h, 80, 1.5) or tcp_ping(h, 22, 1.5):
                    live.append(h)
            evidence.append({"type": "other", "summary": "TCP connect probe fallback (nmap absent or target set > 256)",
                             "targets": hosts[:50]})
            source = "local"

        ctx.add(Result(
            "NET-01", "Host discovery completed", "info",
            description=f"{len(live)} live host(s) of {len(hosts)} probed.",
            asset=",".join(targets), source=source,
            evidence=evidence, data={"live_hosts": live, "probed": len(hosts)}))

    # ----------------------------------------------------------- NET-02 scan --
    def port_scan(self, ctx: Context, targets: list[str]) -> None:
        if not have("nmap"):
            ctx.add(unavailable("NET-02", "TCP port and service inventory", "nmap is not installed on this host."))
            return
        # Find the NET-01 result explicitly: indexing ctx.findings[0] breaks if an
        # earlier check errored, and would silently scan the wrong host set.
        net01 = next((f for f in ctx.findings if f.check_id == "NET-01"), None)
        live = list((net01.data.get("live_hosts") if net01 else []) or [])
        candidates = live or [base_target(t) for t in targets if not is_network(t)][:5]
        if not candidates:
            candidates = base.cidr_hosts(targets[0], limit=32) if targets and is_network(targets[0]) else []
        if not candidates:
            ctx.add(unavailable("NET-02", "TCP port and service inventory", "No live hosts to scan."))
            return
        intensity = ctx.intensity
        if intensity == "light":
            args = ["-Pn", "-T3", "--top-ports", "100", "-sV", "--version-light"]
        elif intensity == "deep":
            args = ["-Pn", "-T3", "-p", "-", "-sV", "--version-all", "--script", "default and safe"]
        else:
            args = ["-Pn", "-T3", "--top-ports", "1000", "-sV"]
        xml_path = ctx.path("nmap_scan.xml")
        argv = ["nmap", *args, "--host-timeout", "300s", "-oX", xml_path, *candidates[:20]]
        res = runner.run(argv, timeout=min(600, 120 + 20 * len(candidates[:20])))
        services = parse_nmap_xml(xml_path)
        ctx.save_text("nmap_stdout.txt", res.stdout[:200000])
        high = [s for s in services if s.get("port") in (21, 23, 445, 1433, 3306, 3389, 5900, 6379, 9200, 11211)]
        ctx.add(Result(
            "NET-02", "TCP port and service inventory", "info",
            description=f"{len(services)} open port(s) across {len(candidates[:20])} host(s); intensity={intensity}.",
            asset=",".join(candidates[:20]), source="live",
            evidence=[res.as_evidence(), artifact(xml_path, "nmap_scan.xml", "xml")],
            data={"services": services[:400], "open_count": len(services)}))
        if high:
            listing = ", ".join(f"{s['host']}:{s['port']}/{s.get('service','?')}" for s in high[:25])
            ctx.add(Result(
                "NET-02b", "Sensitive service ports exposed", "fail", severity="medium",
                description=f"Legacy/administrative services reachable: {listing}",
                asset=",".join(candidates[:20]), source="live", cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe=["CWE-1327"],
                remediation="Restrict administrative and legacy service ports to a management VLAN or VPN.",
                evidence=[{"type": "command_output", "command": "nmap service scan",
                           "stdout": json.dumps(high[:25], indent=2)}],
                data={"exposed": high[:25]}))

    # ------------------------------------------------------------ NET-03 DNS --
    def dns_checks(self, ctx: Context, targets: list[str]) -> None:
        records: dict[str, Any] = {}
        evidence: list[dict] = []
        for t in targets:
            host = hostname_of(t)
            if not host or is_ip(host) or is_network(host):
                continue
            entry: dict[str, Any] = {}
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
                if have("dig"):
                    res = runner.run(["dig", "+short", "+time=4", "+tries=1", rtype, host], timeout=15)
                    vals = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                else:
                    vals = []
                entry[rtype] = vals
            if not any(entry.values()):
                try:
                    entry["A"] = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
                except socket.gaierror as exc:
                    entry["error"] = str(exc)
            records[host] = entry
            evidence.append({"type": "other", "summary": f"DNS records for {host}", "records": entry})
        if not records:
            ctx.add(unavailable("NET-03", "DNS resolution and record harvest",
                                "No DNS names in the target set (IP/CIDR-only assessment)."))
            return
        risky = []
        for host, r in records.items():
            joined = " ".join(str(x) for x in sum((v for v in r.values() if isinstance(v, list)), []))
            if "v=spf1" not in joined.lower():
                risky.append(f"{host}: no SPF record observed")
        ctx.add(Result("NET-03", "DNS resolution and record harvest", "info",
                       description=f"Collected records for {len(records)} name(s).",
                       asset=",".join(records.keys()), source="live", evidence=evidence,
                       data={"records": records}))
        if risky:
            ctx.add(Result("NET-03b", "Missing SPF policy on assessed names", "fail", severity="low",
                           description="; ".join(risky),
                           asset=",".join(records.keys()), source="live", cvss_score=3.7,
                           cwe=["CWE-290"], remediation="Publish an SPF record and align DMARC enforcement.",
                           evidence=[{"type": "other", "summary": "\n".join(risky)}],
                           data={"missing_spf": risky}))

    # ------------------------------------------------------------ NET-04 TLS --
    def tls_checks(self, ctx: Context, targets: list[str]) -> None:
        hosts: list[tuple[str, int]] = []
        tls_ports = (443, 8443, 993, 995, 465, 636, 5061)
        for t in targets:
            host, port = parse_host_port(t)
            if not host:
                continue
            if t.startswith("https://"):
                hosts.append((host, port or 443))
            elif port in tls_ports:
                hosts.append((host, port))
            elif port in (0, 80):
                # Bare domain / http target: also try the conventional TLS port so
                # a plain domain scope entry still gets a real TLS assessment.
                hosts.append((host, 443))
        if not hosts:
            ctx.add(unavailable("NET-04", "TLS configuration assessment",
                                "No TLS-bearing targets in scope (need https:// URL or port 443/8443/...)."))
            return
        results = []
        for host, port in hosts[:20]:
            info = tls_probe(host, port)
            results.append(info)
            if not info.get("connected"):
                continue
            weak = []
            if info.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
                weak.append(f"deprecated {info['version']}")
            if info.get("cipher_bits") and info["cipher_bits"] < 128:
                weak.append(f"weak cipher {info.get('cipher')} ({info.get('cipher_bits')} bits)")
            if info.get("expired"):
                weak.append("certificate expired")
            if info.get("expires_in_days") is not None and info["expires_in_days"] < 15:
                weak.append(f"certificate expires in {info['expires_in_days']} day(s)")
            if info.get("hostname_mismatch"):
                weak.append("certificate hostname mismatch")
            if weak:
                ctx.add(Result("NET-04b", "TLS weakness observed", "fail",
                               severity="medium" if len(weak) > 1 else "low",
                               description=f"{host}:{port} - " + "; ".join(weak),
                               asset=f"{host}:{port}", source="live", cvss_score=5.3,
                               cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                               cwe=["CWE-326", "CWE-295"],
                               remediation="Serve TLS 1.2+ only with AEAD ciphers, a valid hostname-matched certificate and automated renewal.",
                               evidence=[{"type": "other", "summary": f"TLS probe {host}:{port}", "probe": info}],
                               data=info))
        ctx.add(Result("NET-04", "TLS configuration assessment", "info",
                       description=f"Probed {len(results)} TLS endpoint(s) with in-process ssl handshake.",
                       asset=",".join(f"{h}:{p}" for h, p in hosts[:20]), source="live",
                       evidence=[{"type": "other", "summary": "TLS probe results", "results": results}],
                       data={"endpoints": results}))

    # -------------------------------------------------------- NET-05 capture --
    def capture_analysis(self, ctx: Context, targets: list[str]) -> None:
        cap = ctx.params.get("pcap_path")
        if cap and os.path.exists(cap):
            analysis, ev = analyse_pcap(cap, ctx)
            ctx.add(Result("NET-05", "Packet capture analysis", "info",
                           description=f"Analysed supplied capture {os.path.basename(cap)}.",
                           asset=os.path.basename(cap), source="live", evidence=ev, data=analysis))
            return

        iface = ctx.params.get("interface") or default_interface()
        seconds = int(ctx.params.get("capture_seconds", 8 if ctx.intensity == "light" else 15))
        if ctx.mode == "lab" or not have("tcpdump"):
            if not have("tcpdump") and not have("tshark"):
                ctx.add(unavailable("NET-05", "Packet capture and protocol analysis",
                                    "Neither tcpdump nor tshark is installed on this host."))
                return
        pcap = ctx.path(f"capture_{int(time.time())}.pcap")
        res = runner.run(["tcpdump", "-i", iface, "-w", pcap, "-nn", "-q", "-c", "400",
                          "-G", str(seconds), "-W", "1"], timeout=seconds + 40)
        if not os.path.exists(pcap) or os.path.getsize(pcap) < 24:
            ctx.add(unavailable("NET-05", "Packet capture and protocol analysis",
                                f"Capture on {iface} produced no packets. {res.stderr.strip()[:300]}"))
            return
        analysis, ev = analyse_pcap(pcap, ctx)
        ev.append(res.as_evidence())
        ev.append(artifact(pcap, os.path.basename(pcap), "pcap"))
        ctx.add(Result("NET-05", "Packet capture and protocol analysis", "info",
                       description=f"Captured {analysis.get('packets', 0)} packet(s) on {iface} for {seconds}s and decoded protocols.",
                       asset=iface, source="live", evidence=ev, data=analysis))

        anomalies = analysis.get("arp_anomalies") or []
        if anomalies:
            ctx.add(Result("NET-05b", "ARP spoofing indicators in capture", "fail", severity="high",
                           description="; ".join(anomalies[:8]), asset=iface, source="live",
                           cvss_score=7.4, cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                           cwe=["CWE-300"],
                           remediation="Enable Dynamic ARP Inspection / static ARP for gateway MACs on the segment.",
                           evidence=[{"type": "other", "summary": "ARP anomaly detection", "anomalies": anomalies[:20]}],
                           data={"arp_anomalies": anomalies[:20]}))
        dns = analysis.get("dns_queries") or []
        if dns:
            ctx.add(Result("NET-05c", "DNS activity observed", "info",
                           description=f"{len(dns)} distinct DNS query name(s) observed in the capture.",
                           asset=iface, source="live",
                           evidence=[{"type": "other", "summary": "DNS names seen", "names": dns[:60]}],
                           data={"dns_queries": dns[:60]}))

    # -------------------------------------------------------------- NET-06 --
    def arp_review(self, ctx: Context, targets: list[str]) -> None:
        res = runner.run(["ip", "neigh"], timeout=10)
        entries = []
        for line in (res.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] not in ("Repository",):
                ip = parts[0]
                mac = next((p for p in parts if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", p.lower())), None)
                dev = parts[parts.index("dev") + 1] if "dev" in parts else ""
                entries.append({"ip": ip, "mac": mac, "dev": dev, "state": parts[-1]})
        dups: dict[str, list[str]] = {}
        for e in entries:
            # IPv4 only: a single NIC legitimately owns several IPv6 addresses,
            # so only IPv4 collisions indicate cache poisoning.
            if e["mac"] and ":" not in e["ip"]:
                dups.setdefault(e["mac"], []).append(e["ip"]) 
        shared = {m: ips for m, ips in dups.items() if len(set(ips)) > 1}
        if not entries:
            ctx.add(unavailable("NET-06", "ARP / neighbour anomaly review",
                                "Neighbour table is empty on this host."))
            return
        ctx.add(Result("NET-06", "ARP / neighbour table review", "info",
                       description=f"{len(entries)} neighbour entr(ies) inspected; {len(shared)} MAC(s) claimed by more than one IP.",
                       asset=",".join(i["name"] for i in __import__("backend.capabilities", fromlist=["interfaces"]).interfaces()),
                       source="local", evidence=[res.as_evidence()],
                       data={"neighbours": entries, "shared_macs": shared}))
        if shared:
            ctx.add(Result("NET-06b", "Duplicate MAC claims across IPs", "fail", severity="medium",
                           description="One MAC is claiming multiple IP addresses, an ARP-spoofing trait: " +
                                       "; ".join(f"{m} -> {','.join(sorted(set(ips)))}" for m, ips in shared.items()),
                           source="local", cvss_score=5.3, cwe=["CWE-300"],
                           remediation="Investigate the segment for ARP cache poisoning; enforce DAI.",
                           evidence=[{"type": "command_output", "command": "ip neigh", "stdout": res.stdout[:4000]}],
                           data={"shared_macs": shared}))

    # -------------------------------------------------------------- NET-07 --
    def segmentation(self, ctx: Context, targets: list[str]) -> None:
        from backend import capabilities
        ifaces = capabilities.interfaces()
        listening = runner.run(["ss", "-tulpn"], timeout=10)
        exposed = []
        for line in (listening.stdout or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                local = parts[4]
                if local.startswith(("0.0.0.0:", "*:", "[::]:")):
                    exposed.append({"local": local, "process": line.split()[-1][:120]})
        ctx.add(Result("NET-07", "Segmentation and exposure review", "info",
                       description=f"{len(ifaces)} interface(s); {len(exposed)} locally listening socket(s) bound to all addresses.",
                       source="local",
                       evidence=[{"type": "command_output", "command": "ss -tulpn", "stdout": listening.stdout[:8000]}],
                       data={"interfaces": ifaces, "wide_bind": exposed}))
        subnets = []
        for i in ifaces:
            for a in i.get("addresses", []):
                if "/" in a and ":" not in a:
                    try:
                        subnets.append(str(ipaddress.ip_interface(a).network))
                    except ValueError:
                        continue
        if len(set(subnets)) > 1:
            ctx.add(Result("NET-07b", "Multiple routable subnets on one host", "info",
                           description="Host is dual-homed across " + ", ".join(sorted(set(subnets))) +
                                       " - verify that this bridge is intended and filtered.",
                           source="local", cwe=["CWE-923"],
                           remediation="Confirm inter-VLAN routing is restricted by ACL/firewall policy.",
                           evidence=[{"type": "other", "summary": "subnets", "subnets": sorted(set(subnets))}],
                           data={"subnets": sorted(set(subnets))}))

    # -------------------------------------------------------------- NET-08 --
    def ids_integration(self, ctx: Context, targets: list[str]) -> None:
        h = have
        av = []
        for tool, argv in (("suricata", ["suricata", "--build-info"]), ("zeek", ["zeek", "--version"])):
            if h(tool):
                r = runner.run(argv, timeout=15)
                av.append(f"{tool}: {r.stdout.splitlines()[0] if r.stdout else r.stderr[:100]}")
        if not av:
            ctx.add(unavailable("NET-08", "Intrusion detection integration",
                                "Neither Suricata nor Zeek is installed; install one to enable IDS-driven checks. "
                                "The integration interface accepts an eve.json/notice.log path via params.ids_log."))
            return
        log = ctx.params.get("ids_log")
        if log and os.path.exists(log):
            alerts = parse_suricata_eve(log) if log.endswith(".json") else []
            ctx.add(Result("NET-08", "Intrusion detection integration", "info",
                           description=f"Parsed {len(alerts)} IDS alert(s) from {os.path.basename(log)}.",
                           source="live", evidence=[{"type": "other", "summary": "IDS alerts", "alerts": alerts[:50]}],
                           data={"alerts": alerts[:200]}))
        else:
            ctx.add(Result("NET-08", "Intrusion detection integration", "info",
                           description="IDS binaries present: " + "; ".join(av) +
                                       ". Supply params.ids_log (eve.json) to correlate alerts.",
                           source="local", data={"available": av}))


# ------------------------------------------------------------------ helpers --
def base_target(t: str) -> str:
    return t.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def hostname_of(t: str) -> str:
    return base_target(t)


def is_network(t: str) -> bool:
    try:
        ipaddress.ip_network(t, strict=False)
        return "/" in t
    except ValueError:
        return False


def is_ip(t: str) -> bool:
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def parse_host_port(t: str) -> tuple[str | None, int]:
    host = base_target(t)
    if not host:
        return None, 0
    if t.startswith("https://"):
        return host, 443
    if t.startswith("http://"):
        return host, 80
    rest = t.split("//", 1)[-1]
    if ":" in rest:
        part = rest.split("/")[0]
        try:
            return part.split(":")[0], int(part.split(":")[1])
        except (IndexError, ValueError):
            return host, 0
    return host, 0


def tcp_ping(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def tls_probe(host: str, port: int) -> dict:
    import datetime as dt
    out: dict[str, Any] = {"host": host, "port": port, "connected": False}
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                out.update({
                    "connected": True, "version": ssock.version(), "cipher": ssock.cipher()[0],
                    "cipher_bits": ssock.cipher()[2], "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"), "sans": cert.get("subjectAltName", []),
                    "verified": True,
                })
                if cert.get("notAfter"):
                    exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
                    days = (exp - dt.datetime.now(dt.timezone.utc)).days
                    out["expires_in_days"] = days
                    out["expired"] = days < 0
    except ssl.SSLCertVerificationError as exc:
        out.update({"connected": True, "verified": False, "hostname_mismatch": "hostname" in str(exc).lower(),
                    "verify_error": str(exc)[:300]})
        try:
            insecure = _unverified_context()  # evidence gathering only
            with socket.create_connection((host, port), timeout=6) as sock:
                with insecure.wrap_socket(sock, server_hostname=host) as s2:
                    out["version"] = s2.version()
                    out["cipher"] = s2.cipher()[0]
        except OSError:
            pass
    except OSError as exc:
        out["error"] = str(exc)[:300]
    return out


def _safe_xml_parse(path: str):
    """Parse XML defensively.

    The assessment may be pointed at an nmap XML file supplied by the operator, so
    the document is untrusted input. defusedxml blocks entity expansion
    (billion-laughs / XXE) when present; the stdlib parser is the fallback with
    entity resolution disabled.
    """
    try:
        from defusedxml import ElementTree as SafeET  # type: ignore
        return SafeET.parse(path).getroot()
    except ImportError:
        import xml.etree.ElementTree as ET
        parser = ET.XMLParser()
        parser.parser.DefaultHandler = lambda x: None
        parser.parser.EntityDeclHandler = lambda *a: None
        return ET.parse(path, parser=parser).getroot()


def _unverified_context() -> ssl.SSLContext:
    """TLS context that deliberately does not validate (assessment evidence only).

    A TLS posture check must connect to expired or mismatched certificates in
    order to report on them. Built through the public API so it does not depend on
    the private `ssl._create_unverified_context`.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def parse_nmap_xml(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    try:
        root = _safe_xml_parse(path)
    except Exception:
        return []
    if root is None:
        return []
    services = []
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "?"
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            services.append({
                "host": ip, "hostname": hostname, "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
    return services


def default_interface() -> str:
    res = runner.run(["ip", "route", "get", "8.8.8.8"], timeout=8)
    for line in (res.stdout or "").splitlines():
        if "dev" in line:
            return line.split("dev")[1].split()[0]
    return "eth0"


def analyse_pcap(pcap: str, ctx: Context) -> tuple[dict, list[dict]]:
    evidence: list[dict] = []
    data: dict[str, Any] = {"pcap": pcap, "packets": 0}
    if have("tshark"):
        proto = runner.run(["tshark", "-r", pcap, "-q", "-z", "io,phs"], timeout=120)
        convs = runner.run(["tshark", "-r", pcap, "-q", "-z", "conv,tcp"], timeout=120)
        endpoints = runner.run(["tshark", "-r", pcap, "-q", "-z", "endpoints,ip"], timeout=120)
        dnsr = runner.run(["tshark", "-r", pcap, "-Y", "dns.flags.response==0", "-T", "fields",
                           "-e", "dns.qry.name"], timeout=120)
        arpr = runner.run(["tshark", "-r", pcap, "-Y", "arp", "-T", "fields", "-e", "arp.src.proto_ipv4",
                           "-e", "arp.src.hw_mac"], timeout=120)
        tlsr = runner.run(["tshark", "-r", pcap, "-Y", "tls.handshake.type==1", "-T", "fields",
                           "-e", "tls.handshake.extensions_server_name"], timeout=120)
        count = runner.run(["tshark", "-r", pcap, "-T", "fields", "-e", "frame.number"], timeout=120)
        data["packets"] = len([l for l in count.stdout.splitlines() if l.strip()])
        data["protocol_hierarchy"] = proto.stdout[:6000]
        data["tcp_conversations"] = parse_conv(convs.stdout)
        data["ip_endpoints"] = parse_endpoints(endpoints.stdout)
        data["dns_queries"] = sorted({l.strip() for l in dnsr.stdout.splitlines() if l.strip()})
        data["tls_sni"] = sorted({l.strip() for l in tlsr.stdout.splitlines() if l.strip()})
        pairs: dict[str, set] = {}
        for line in arpr.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].strip() and parts[1].strip():
                pairs.setdefault(parts[1].strip().lower(), set()).add(parts[0].strip())
        data["arp_anomalies"] = [f"MAC {m} seen claiming {', '.join(sorted(ips))}"
                                 for m, ips in pairs.items() if len(ips) > 1]
        evidence = [proto.as_evidence(), convs.as_evidence(), dnsr.as_evidence()]
        ctx.save_text("protocol_hierarchy.txt", proto.stdout)
    elif have("tcpdump"):
        res = runner.run(["tcpdump", "-nn", "-r", pcap, "-c", "2000"], timeout=120)
        data["packets"] = len([l for l in res.stdout.splitlines() if l.strip()])
        data["summary"] = res.stdout[:20000]
        evidence = [res.as_evidence()]
    else:
        data["error"] = "no packet decoder installed"
    return data, evidence


def parse_conv(text: str) -> list[dict]:
    rows = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 10 and re.match(r"^\d+\.\d+\.\d+\.\d+:\d+$", parts[0]):
            rows.append({"a": parts[0], "b": parts[2], "packets": parts[-6] if len(parts) > 8 else "",
                         "bytes": parts[-5] if len(parts) > 8 else ""})
    return rows[:100]


def parse_endpoints(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if parts and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            out.append({"ip": parts[0], "packets": parts[1] if len(parts) > 1 else "",
                        "bytes": parts[2] if len(parts) > 2 else ""})
    return out[:100]


def parse_suricata_eve(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "alert":
                al = ev.get("alert", {})
                out.append({"ts": ev.get("timestamp"), "signature": al.get("signature"),
                            "severity": al.get("severity"), "src": ev.get("src_ip"), "dst": ev.get("dest_ip")})
    return out
