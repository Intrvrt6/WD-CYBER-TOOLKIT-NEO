"""Module B - MITM Security.

Passive-first: certificate validation over the wire, TLS downgrade/mismatch
detection, ARP cache integrity, DNS answer consistency, gateway/route sanity.
Active interception (ARP spoof, DNS rewrite, rogue gateway) is only attempted
when the assessment runs in live mode AND params.allow_active is true; every
active action is recorded with its exact command and a rollback note.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl

from backend import runner
from engines.base import Context, Result, have, unavailable
from engines.network.engine import base_target, default_interface, parse_host_port, tls_probe


class MITMEngine:
    module = "mitm"
    title = "Module B - MITM Security"
    description = "Certificate validation, TLS interception posture, ARP cache integrity, DNS consistency, rogue gateway review, controlled active interception."
    checks = [
        ("MITM-01", "Certificate chain validation", True),
        ("MITM-02", "TLS downgrade and interception readiness", True),
        ("MITM-03", "ARP cache integrity", True),
        ("MITM-04", "DNS answer consistency", True),
        ("MITM-05", "Gateway and route sanity", True),
        ("MITM-06", "Active ARP/DNS interception (authorized)", True),
        ("MITM-07", "mitmproxy interception readiness", False),
    ]

    def run(self, ctx: Context) -> list[Result]:
        steps = [self.cert_validation, self.tls_interception, self.arp_integrity,
                 self.dns_consistency, self.gateway_sanity, self.active_interception,
                 self.mitmproxy_readiness]
        for i, fn in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("MITM-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining MITM checks were not executed.", source="local"))
                break
            try:
                fn(ctx)
            except Exception as exc:
                ctx.add(Result(f"MITM-{i+1:02d}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    def _https_hosts(self, ctx: Context) -> list[tuple[str, int]]:
        out = []
        for t in ctx.targets:
            if t.startswith("https://") or parse_host_port(t)[1] in (443, 8443):
                h, p = parse_host_port(t)
                if h:
                    out.append((h, p or 443))
        return out[:20]

    # ------------------------------------------------------------ MITM-01 --
    def cert_validation(self, ctx: Context) -> None:
        hosts = self._https_hosts(ctx)
        if not hosts:
            ctx.add(unavailable("MITM-01", "Certificate chain validation",
                                "No HTTPS endpoints in scope."))
            return
        rows = []
        for host, port in hosts:
            probe = tls_probe(host, port)
            rows.append(probe)
            if probe.get("connected") and not probe.get("verified", False):
                ctx.add(Result("MITM-01b", "Invalid certificate trust chain", "fail", severity="high",
                               description=f"{host}:{port} - client-side validation failed: {probe.get('verify_error','unknown')}",
                               asset=f"{host}:{port}", source="live", cvss_score=7.4,
                               cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                               cwe=["CWE-295"],
                               remediation="Deploy a certificate that chains to a public CA and matches the served hostname.",
                               evidence=[{"type": "other", "summary": f"TLS probe {host}:{port}", "probe": probe}],
                               data=probe))
            issuer = (probe.get("issuer") or {}).get("organizationName") or (probe.get("issuer") or {}).get("commonName")
            if issuer and any(k in issuer.lower() for k in ("mitm", "proxy", "fortinet", "zscaler", "bluecoat", "squid")):
                ctx.add(Result("MITM-01c", "TLS interception device in path", "info",
                               description=f"{host}:{port} is answered by an interception CA '{issuer}' - traffic is being re-signed inline.",
                               asset=f"{host}:{port}", source="live", cwe=["CWE-319"],
                               evidence=[{"type": "other", "summary": "issuer", "issuer": probe.get("issuer")}],
                               data={"issuer": probe.get("issuer")}))
        ctx.add(Result("MITM-01", "Certificate chain validation", "info",
                       description=f"Validated {len(rows)} certificate chain(s).",
                       asset=",".join(f"{h}:{p}" for h, p in hosts), source="live",
                       evidence=[{"type": "other", "summary": "chain results", "results": rows}],
                       data={"chains": rows}))

    # ------------------------------------------------------------ MITM-02 --
    def tls_interception(self, ctx: Context) -> None:
        hosts = self._https_hosts(ctx)
        if not hosts:
            ctx.add(unavailable("MITM-02", "TLS downgrade and interception readiness",
                                "No HTTPS endpoints in scope."))
            return
        rows = []
        for host, port in hosts:
            supported = []
            for proto_name, proto in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                                      ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
                try:
                    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    c.check_hostname = False
                    c.verify_mode = ssl.CERT_NONE
                    c.minimum_version = proto
                    c.maximum_version = proto
                    with socket.create_connection((host, port), timeout=5) as s:
                        with c.wrap_socket(s, server_hostname=host):
                            supported.append(proto_name)
                except (ssl.SSLError, OSError):
                    continue
            rows.append({"host": host, "port": port, "supported": supported})
            legacy = [p for p in supported if p in ("TLSv1", "TLSv1.1")]
            if legacy:
                ctx.add(Result("MITM-02b", "Legacy TLS versions accepted", "fail", severity="medium",
                               description=f"{host}:{port} still negotiates {'/'.join(legacy)}, widening downgrade-interception exposure.",
                               asset=f"{host}:{port}", source="live", cvss_score=5.9,
                               cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
                               cwe=["CWE-326", "CWE-757"],
                               remediation="Disable TLS 1.0/1.1 and enforce TLS 1.2+ with HSTS.",
                               evidence=[{"type": "other", "summary": "protocol matrix", "row": rows[-1]}],
                               data=rows[-1]))
        ctx.add(Result("MITM-02", "TLS downgrade and interception readiness", "info",
                       description=f"Protocol matrix collected for {len(rows)} endpoint(s).",
                       asset=",".join(f"{r['host']}:{r['port']}" for r in rows), source="live",
                       evidence=[{"type": "other", "summary": "matrix", "matrix": rows}], data={"matrix": rows}))

    # ------------------------------------------------------------ MITM-03 --
    def arp_integrity(self, ctx: Context) -> None:
        if not have("arping"):
            ctx.add(unavailable("MITM-03", "ARP cache integrity",
                                "arping is not installed; install iputils-arping for active ARP verification."))
            return
        gw = gateway()
        if not gw:
            ctx.add(unavailable("MITM-03", "ARP cache integrity", "No default gateway detected on this host."))
            return
        iface = default_interface()
        res = runner.run(["arping", "-c", "3", "-I", iface, gw], timeout=30)
        claimed = sorted(set(re.findall(r"\[([0-9a-fA-F:]{17})\]", res.stdout)))
        neigh = runner.run(["ip", "neigh", "show", gw], timeout=10)
        cached = re.findall(r"([0-9a-fA-F:]{17})", neigh.stdout)
        mismatch = bool(claimed and cached and claimed[0].lower() not in [c.lower() for c in cached])
        ctx.add(Result("MITM-03", "ARP cache integrity", "info",
                       description=f"Gateway {gw} answered ARP with {', '.join(claimed) or 'no reply'}; cache holds {', '.join(cached) or 'nothing'}.",
                       asset=f"{gw} via {iface}", source="live",
                       evidence=[res.as_evidence(), neigh.as_evidence()],
                       data={"gateway": gw, "claimed_macs": claimed, "cached_macs": cached}))
        if mismatch:
            ctx.add(Result("MITM-03b", "Gateway MAC differs from ARP cache", "fail", severity="high",
                           description=f"Live ARP reply from {gw} returned {claimed[0]} while the cache holds {cached[0]} - possible cache poisoning.",
                           asset=gw, source="live", cvss_score=7.4, cwe=["CWE-300"],
                           remediation="Clear and re-learn the cache, then enforce static gateway ARP or DAI.",
                           evidence=[res.as_evidence()],
                           data={"claimed": claimed, "cached": cached}))

    # ------------------------------------------------------------ MITM-04 --
    def dns_consistency(self, ctx: Context) -> None:
        names = [base_target(t) for t in ctx.targets if not re.match(r"^\d+\.\d+\.\d+\.\d+$", base_target(t))]
        names = [n for n in names if n and "." in n][:10]
        if not names:
            ctx.add(unavailable("MITM-04", "DNS answer consistency", "No DNS names in scope."))
            return
        rows = []
        resolvers = ctx.params.get("resolvers") or ["1.1.1.1", "8.8.8.8"]
        if not have("dig"):
            ctx.add(unavailable("MITM-04", "DNS answer consistency", "dig is not installed."))
            return
        for name in names:
            answers: dict[str, list[str]] = {}
            for r in resolvers:
                res = runner.run(["dig", "+short", "+time=4", "+tries=1", f"@{r}", "A", name], timeout=15)
                answers[r] = sorted({l.strip() for l in res.stdout.splitlines()
                                     if l.strip() and not l.strip().endswith(".")})
            system = runner.run(["dig", "+short", "+time=4", "+tries=1", "A", name], timeout=15)
            answers["system"] = sorted({l.strip() for l in system.stdout.splitlines() if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())})
            rows.append({"name": name, "answers": answers})
            nonempty = {k: set(v) for k, v in answers.items() if v}
            if len({frozenset(v) for v in nonempty.values()}) > 1:
                ctx.add(Result("MITM-04b", "Inconsistent DNS resolution across resolvers", "fail", severity="medium",
                               description=f"{name} resolved differently (split-horizon or spoofed answer): " +
                                           json.dumps({k: sorted(v) for k, v in nonempty.items()}),
                               asset=name, source="live", cvss_score=5.9, cwe=["CWE-350"],
                               remediation="Enforce DNSSEC validation and a single authoritative resolver path.",
                               evidence=[{"type": "other", "summary": "resolver matrix", "row": rows[-1]}],
                               data=rows[-1]))
        ctx.add(Result("MITM-04", "DNS answer consistency", "info",
                       description=f"Compared answers for {len(rows)} name(s) across {len(resolvers)} resolver(s) plus the system resolver.",
                       source="live", evidence=[{"type": "other", "summary": "matrix", "matrix": rows}],
                       data={"matrix": rows}))

    # ------------------------------------------------------------ MITM-05 --
    def gateway_sanity(self, ctx: Context) -> None:
        routes = runner.run(["ip", "route"], timeout=10)
        gw = gateway()
        default_count = len([l for l in routes.stdout.splitlines() if l.startswith("default")])
        ctx.add(Result("MITM-05", "Gateway and route sanity", "info",
                       description=f"Default gateway {gw or 'none'}; {default_count} default route(s) present.",
                       source="local", evidence=[routes.as_evidence()],
                       data={"gateway": gw, "default_routes": default_count}))
        if default_count > 1:
            ctx.add(Result("MITM-05b", "Multiple default routes", "fail", severity="low",
                           description=f"{default_count} default routes exist, so traffic may egress through an unexpected path.",
                           source="local", cvss_score=3.1, cwe=["CWE-923"],
                           remediation="Remove redundant default routes or pin metrics deliberately.",
                           evidence=[routes.as_evidence()], data={"routes": routes.stdout[:3000]}))

    # ------------------------------------------------------------ MITM-06 --
    def active_interception(self, ctx: Context) -> None:
        """Only with explicit params.allow_active - writes traffic on the segment."""
        if not ctx.params.get("allow_active"):
            ctx.add(Result("MITM-06", "Active ARP/DNS interception", "info",
                           description="Skipped: active interception requires params.allow_active=true (it injects frames).",
                           source="local",
                           evidence=[{"type": "other",
                                      "summary": "active interception not enabled for this assessment",
                                      "params_allow_active": False,
                                      "reason": "opted out; no frames were transmitted"}],
                           data={"performed": False}))
            return
        if ctx.mode != "live":
            ctx.add(unavailable("MITM-06", "Active ARP/DNS interception",
                                "Active interception requires live mode with a real interface."))
            return
        if os.name != "posix" or not have("ip"):
            ctx.add(unavailable("MITM-06", "Active ARP/DNS interception", "Requires Linux iproute2 + scapy."))
            return
        gw = gateway()
        iface = default_interface()
        raw_ok = True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
        except OSError:
            raw_ok = False
        ctx.add(Result("MITM-06", "Active ARP/DNS interception", "info",
                       description=(f"Active interception armed on {iface} toward gateway {gw}; raw socket "
                                    f"{'available' if raw_ok else 'NOT available'}. "
                                    "Execution requires scapy ARP reply injection and is only performed on request."),
                       source="live",
                       evidence=[{"type": "other",
                                  "summary": f"interception armed on {iface}",
                                  "gateway": gw, "interface": iface, "raw_socket": raw_ok,
                                  "rollback": "gratuitous ARP with the true gateway MAC restores caches"}],
                       data={"gateway": gw, "interface": iface, "raw_socket": raw_ok,
                             "rollback": "gratuitous ARP with the true gateway MAC restores caches"}))
        if ctx.params.get("execute_arp_spoof"):
            try:
                from scapy.all import ARP, Ether, sendp  # type: ignore
                my_mac = get_mac(iface)
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gw, hwsrc=my_mac,
                                                          pdst=gw, hwdst=gw)
                sendp(pkt, iface=iface, count=int(ctx.params.get("arp_count", 3)), verbose=False)
                ctx.add(Result("MITM-06b", "Gratuitous ARP frames transmitted", "info",
                               description=f"Sent {ctx.params.get('arp_count',3)} crafted ARP frame(s) on {iface} claiming {gw}.",
                               source="live",
                               evidence=[{"type": "other", "summary": "scapy ARP sendp",
                                          "frame": f"Ether/ARP(op=2,psrc={gw},hwsrc={my_mac})"}],
                               data={"frames": int(ctx.params.get("arp_count", 3))}))
            except Exception as exc:
                ctx.add(Result("MITM-06b", "ARP frame injection failed", "error",
                               description=f"{type(exc).__name__}: {exc}", source="live"))

    # ------------------------------------------------------------ MITM-07 --
    def mitmproxy_readiness(self, ctx: Context) -> None:
        if not have("mitmproxy"):
            ctx.add(unavailable("MITM-07", "mitmproxy interception readiness",
                                "mitmproxy is not installed; install it to run an intercepting proxy."))
            return
        res = runner.run(["mitmproxy", "--version"], timeout=15)
        version = res.stdout.strip().splitlines()[0] if res.stdout.strip() else res.stderr.strip()[:120]
        ctx.add(Result("MITM-07", "mitmproxy interception readiness", "info",
                       description=f"mitmproxy available: {version}. Start it with 'mitmproxy -p 8081' and point the client proxy at it.",
                       source="local", evidence=[res.as_evidence()], data={"version": version}))


# ------------------------------------------------------------------ helpers --
def gateway() -> str | None:
    res = runner.run(["ip", "route", "show", "default"], timeout=8)
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", res.stdout or "")
    return m.group(1) if m else None


def get_mac(iface: str) -> str:
    path = f"/sys/class/net/{iface}/address"
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "02:00:00:00:00:01"
