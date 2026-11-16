"""Module J - Web Application Penetration Testing.

One shared engine that every web-facing module reuses. All findings are
collected with real HTTP requests: nothing is inferred from a template or
assumed from a header name alone.

Every result carries source="live" because each one is derived from an actual
response captured during this run. A check that could not obtain a response
reports `unavailable` with the transport error instead of a fabricated score.
"""
from __future__ import annotations

import json
import os
import random
import re
import string
import time
from typing import Any
from urllib.parse import urlparse

from backend import runner
from engines import base
from engines.base import Context, Result, artifact, have, unavailable
from engines.network.engine import parse_host_port, tls_probe

# Baseline security headers worth reporting on any web origin. Absence of an
# optional header is reported as an observation, never as a vulnerability by
# itself - impact has to be shown separately.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (only meaningful over HTTPS)",
    "content-security-policy": "CSP - limits script injection impact",
    "x-content-type-options": "blocks MIME sniffing",
    "x-frame-options": "clickjacking control (legacy; CSP frame-ancestors preferred)",
    "referrer-policy": "controls Referer leakage",
    "permissions-policy": "restricts powerful browser features",
}

# Header/body signatures used for a conservative technology hint list.
TECH_SIGNATURES = [
    ("server", re.compile(r"nginx/?([\d.]*)", re.I), "nginx"),
    ("server", re.compile(r"apache/?([\d.]*)", re.I), "Apache httpd"),
    ("server", re.compile(r"Microsoft-IIS/?([\d.]*)", re.I), "Microsoft IIS"),
    ("server", re.compile(r"SimpleHTTP/([\d.]+) Python/([\d.]+)", re.I), "Python http.server"),
    ("x-powered-by", re.compile(r"PHP/?([\d.]*)", re.I), "PHP"),
    ("x-powered-by", re.compile(r"ASP\.NET", re.I), "ASP.NET"),
    ("x-powered-by", re.compile(r"Express", re.I), "Express (Node.js)"),
    ("x-generator", re.compile(r"(.+)", re.I), "generator header"),
    ("set-cookie", re.compile(r"JSESSIONID", re.I), "Java servlet container"),
    ("set-cookie", re.compile(r"PHPSESSID", re.I), "PHP session"),
    ("set-cookie", re.compile(r"laravel_session", re.I), "Laravel"),
    ("set-cookie", re.compile(r"csrftoken", re.I), "Django"),
    ("x-aspnet-version", re.compile(r"([\d.]+)", re.I), "ASP.NET version disclosed"),
]

# Small built-in discovery list. Deliberately short: the goal is to show which
# of these actually exist, not to brute-force the whole application.
DEFAULT_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/index.html", "/index.php",
    "/admin", "/admin/", "/login", "/login.php", "/api", "/api/", "/api/v1",
    "/.git/HEAD", "/.env", "/server-status", "/phpinfo.php", "/info.php",
    "/backup.zip", "/config.php", "/wp-login.php", "/health", "/status", "/debug",
]

INTERESTING_PATH = re.compile(r"(\.git|\.env|\.svn|backup|\.bak|\.sql|\.zip|server-status|"
                              r"phpinfo|debug|admin|actuator|swagger|openapi|\.old$)", re.I)

STACK_TRACE_MARKERS = [
    "Traceback (most recent call last)", "Fatal error:", "Warning: ", "Notice: ",
    "Microsoft OLE DB Provider", "System.NullReferenceException",
    "org.springframework", "at java.", "Stack trace:", "Whoops",
]
INFO_DISCLOSURE_MARKERS = [
    "root:x:0:0", "DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS_KEY_ID", "PRIVATE KEY",
    "ref: refs/heads/", "Server at ", "phpinfo()", "APACHE_RUN_USER",
]


class WebAppEngine:
    module = "webapp"
    title = "Module J - Web Application Pentest"
    description = ("Live HTTP fingerprinting, TLS posture, bounded path discovery, cookie/session "
                   "flags, CORS policy, information disclosure, reflection surface and a nuclei baseline.")
    checks = [
        ("WEB-01", "HTTP fingerprint and security headers", True),
        ("WEB-02", "TLS / HTTPS posture", True),
        ("WEB-03", "Content and path discovery", True),
        ("WEB-04", "Cookie and session flags", True),
        ("WEB-05", "CORS policy probe", True),
        ("WEB-06", "Information disclosure", True),
        ("WEB-07", "Injection-surface indicators (reflection)", True),
        ("WEB-08", "Nuclei baseline scan", True),
    ]

    def __init__(self) -> None:
        self._session_state: dict[str, dict] = {}

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        targets = [normalise_target(t) for t in ctx.targets if t and t.strip()]
        if not targets:
            ctx.add(unavailable("WEB-01", "HTTP fingerprint and security headers",
                                "No HTTP(S) target supplied in ctx.targets."))
            return ctx.findings
        steps = [("WEB-01", self.fingerprint), ("WEB-02", self.tls_posture),
                 ("WEB-03", self.path_discovery), ("WEB-04", self.cookie_flags),
                 ("WEB-05", self.cors_probe), ("WEB-06", self.info_disclosure),
                 ("WEB-07", self.reflection), ("WEB-08", self.nuclei_baseline)]
        for i, (cid, fn) in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("WEB-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining web checks were not executed.", source="live"))
                break
            try:
                fn(ctx, targets)
            except Exception as exc:
                ctx.add(Result(f"{cid}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    # ------------------------------------------------------------ WEB-01 -----
    def fingerprint(self, ctx: Context, targets: list[str]) -> None:
        records: list[dict] = []
        for target in targets[:5]:
            resp = http_get(target, timeout=float(ctx.params.get("http_timeout", 8)))
            if not resp.get("ok"):
                records.append({"url": target, "error": resp.get("error", "no response")})
                continue
            headers = {k.lower(): v for k, v in resp["headers"].items()}
            present = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
            missing = [h for h in SECURITY_HEADERS if h not in headers]
            tech = []
            for hname, pattern, label in TECH_SIGNATURES:
                raw = headers.get(hname, "")
                m = pattern.search(raw)
                if m:
                    tech.append({"product": label, "header": hname,
                                 "value": m.group(0)[:120],
                                 "version": next((g for g in m.groups() if g and re.match(r"^[\d.]+$", g)), "")})
            body_markers = []
            for marker, label in (("wp-content", "WordPress"), ("__NEXT_DATA__", "Next.js"),
                                  ("ng-version", "Angular"), ("data-reactroot", "React"),
                                  ("csrfmiddlewaretoken", "Django"), ("_csrf", "CSRF token field")):
                if marker.lower() in resp["body"].lower():
                    body_markers.append(label)
            records.append({
                "url": target, "final_url": resp["final_url"], "status": resp["status"],
                "elapsed_s": resp["elapsed_s"], "server": headers.get("server", ""),
                "powered_by": headers.get("x-powered-by", ""),
                "content_type": headers.get("content-type", ""),
                "content_length": len(resp["body"]),
                "redirects": resp["redirects"],
                "headers": headers, "security_headers_present": present,
                "security_headers_missing": missing,
                "tech": tech, "body_markers": sorted(set(body_markers)),
                "body_sha256": resp["body_sha256"],
            })
            self._session_state.setdefault(target, {})["fingerprint"] = records[-1]

        good = [r for r in records if "error" not in r]
        if not good:
            ctx.add(unavailable("WEB-01", "HTTP fingerprint and security headers",
                                "No target answered HTTP: " +
                                "; ".join(f"{r['url']}: {r['error']}" for r in records[:5])))
            return
        art = ctx.save_text("web_fingerprint.json", json.dumps(records, indent=2))
        ctx.add(Result(
            "WEB-01", "HTTP fingerprint and security headers", "info",
            description=(f"{len(good)}/{len(records)} target(s) answered. "
                         + "; ".join(f"{r['url']} -> HTTP {r['status']}"
                                     f" server={r['server'] or '(none)'}"
                                     f" x-powered-by={r['powered_by'] or '(none)'}"
                                     f" tech={','.join(t['product'] for t in r['tech']) or '(none)'}"
                                     for r in good[:3])),
            asset=", ".join(r["url"] for r in good), source="live",
            evidence=[{"type": "other", "summary": "observed headers per target",
                       "records": [{k: r[k] for k in
                                    ("url", "status", "server", "powered_by",
                                     "security_headers_present", "security_headers_missing")}
                                   for r in good]},
                      {**art, "type": "file"}],
            data={"records": records}))

        missing_any = [r for r in good if r["security_headers_missing"]]
        if missing_any:
            ctx.add(Result(
                "WEB-01b", "Security response headers not set", "info", severity="low",
                description="; ".join(f"{r['url']}: missing {', '.join(r['security_headers_missing'])}"
                                      for r in missing_any[:5]),
                asset=", ".join(r["url"] for r in missing_any), source="live",
                remediation=("Set HSTS on HTTPS origins, a Content-Security-Policy, "
                             "X-Content-Type-Options: nosniff, a Referrer-Policy and CSP "
                             "frame-ancestors. These are hardening controls; the exact impact "
                             "depends on the application's injection surface."),
                evidence=[{"type": "other", "summary": "missing header sets",
                           "rows": [{"url": r["url"], "missing": r["security_headers_missing"],
                                     "present": r["security_headers_present"]} for r in missing_any]}],
                data={"missing": [{"url": r["url"], "missing": r["security_headers_missing"]}
                                  for r in missing_any]}))
        versions = [t for r in good for t in r["tech"] if t.get("version")]
        if versions:
            ctx.add(Result(
                "WEB-01c", "Server/product version disclosed in headers", "info", severity="low",
                description="; ".join(f"{r['url']}: {t['product']} {t['version']} ({t['header']}: "
                                      f"{t['value']})" for r in good for t in r["tech"] if t.get("version")),
                asset=", ".join(r["url"] for r in good), source="live",
                remediation="Suppress version tokens (server_tokens off, X-Powered-By removal).",
                evidence=[{"type": "other", "summary": "version tokens", "tokens": versions[:15]}],
                data={"versions": versions[:15]}))

    # ------------------------------------------------------------ WEB-02 -----
    def tls_posture(self, ctx: Context, targets: list[str]) -> None:
        endpoints: list[tuple[str, int, str]] = []
        for target in targets[:5]:
            parsed = urlparse(target)
            host = parsed.hostname or ""
            if not host:
                continue
            # Use the explicit port from the URL first: parse_host_port() collapses
            # any https:// URL to 443, which would hide a listener on e.g. :8443.
            if parsed.port:
                port = parsed.port
            elif parsed.scheme == "https":
                port = 443
            else:
                port = 80
            endpoints.append((host, port, target))
        if not endpoints:
            ctx.add(unavailable("WEB-02", "TLS / HTTPS posture",
                                "Could not derive a host:port pair from ctx.targets."))
            return
        probes = []
        for host, port, target in endpoints:
            info = tls_probe(host, port)
            info["target"] = target
            # tls_probe() only records cipher bits on the verified path; fill the
            # negotiated suite strength from a second handshake so the report never
            # prints a bare "Nonebit".
            if info.get("connected") and info.get("cipher_bits") is None:
                bits = cipher_bits(host, port)
                if bits:
                    info["cipher_bits"] = bits
            probes.append(info)
        art = ctx.save_text("web_tls.json", json.dumps(probes, indent=2))
        connected = [p for p in probes if p.get("connected") and p.get("version")]
        if not connected:
            ctx.add(unavailable(
                "WEB-02", "TLS / HTTPS posture",
                "TLS handshake did not complete for any endpoint, so no protocol, cipher or "
                "certificate posture could be assessed. " +
                "; ".join(f"{p['host']}:{p['port']}: {p.get('error') or p.get('verify_error') or 'no TLS listener'}"
                          for p in probes[:5]),
                asset=", ".join(f"{p['host']}:{p['port']}" for p in probes)))
            ctx.findings[-1].evidence.append({**art, "type": "file"})
            return
        ctx.add(Result(
            "WEB-02", "TLS / HTTPS posture", "info",
            description="; ".join(f"{p['host']}:{p['port']} {p.get('version')} {p.get('cipher')} "
                                  f"{p.get('cipher_bits') or '?'}bit verified={p.get('verified')} "
                                  f"expires_in={p.get('expires_in_days')}d"
                                  for p in connected[:5]),
            asset=", ".join(f"{p['host']}:{p['port']}" for p in connected), source="live",
            evidence=[{"type": "other", "summary": "TLS probe results", "probes": probes},
                      {**art, "type": "file"}],
            data={"probes": probes}))

        weak = []
        for p in connected:
            issues = []
            if p.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
                issues.append(f"deprecated {p['version']}")
            if p.get("cipher_bits") and p["cipher_bits"] < 128:
                issues.append(f"weak cipher {p.get('cipher')}")
            if p.get("expired"):
                issues.append("certificate expired")
            elif p.get("expires_in_days") is not None and p["expires_in_days"] < 15:
                issues.append(f"expires in {p['expires_in_days']}d")
            if p.get("hostname_mismatch"):
                issues.append("hostname mismatch")
            if p.get("verified") is False:
                issues.append("certificate did not verify")
            if issues:
                weak.append({"endpoint": f"{p['host']}:{p['port']}", "issues": issues})
        if weak:
            ctx.add(Result(
                "WEB-02b", "TLS weakness observed on web endpoint", "fail", severity="medium",
                description="; ".join(f"{w['endpoint']}: {', '.join(w['issues'])}" for w in weak[:5]),
                asset=", ".join(w["endpoint"] for w in weak), source="live", cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe=["CWE-326", "CWE-295"],
                remediation="Serve TLS 1.2+ with AEAD suites, a valid renewal-automated "
                            "certificate matching the hostname, and HSTS on the origin.",
                evidence=[{"type": "other", "summary": "TLS issues", "weak": weak}],
                data={"weak": weak}))

    # ------------------------------------------------------------ WEB-03 -----
    def path_discovery(self, ctx: Context, targets: list[str]) -> None:
        target = targets[0]
        wordlist = ctx.path("web_wordlist.txt")
        words = ctx.params.get("web_wordlist") or DEFAULT_PATHS
        with open(wordlist, "w", encoding="utf-8") as fh:
            for w in words:
                fh.write(w.lstrip("/") + "\n")

        found: list[dict] = []
        engine_used = ""
        if have("ffuf"):
            engine_used = "ffuf"
            out = ctx.path("ffuf_web.json")
            argv = ["ffuf", "-u", target.rstrip("/") + "/FUZZ", "-w", wordlist,
                    "-mc", "200,201,204,301,302,307,401,403,405", "-t", "20",
                    "-timeout", "5", "-s", "-of", "json", "-o", out]
            if target.startswith("https://"):
                argv.append("-k")   # lab targets frequently use self-signed certificates
            res = runner.run(argv, timeout=int(ctx.params.get("ffuf_timeout", 60)))
            found = parse_ffuf(out)
            evidence_cmd = res.as_evidence()
            if not found and res.timed_out:
                engine_used = "ffuf (timed out, fell back to httpx)"
        else:
            evidence_cmd = None

        if not found:
            engine_used = engine_used if engine_used.startswith("ffuf (") else "httpx path probe"
            for path in DEFAULT_PATHS:
                url = target.rstrip("/") + path
                r = http_get(url, timeout=float(ctx.params.get("http_timeout", 8)), read_body=True)
                if r.get("ok") and r["status"] < 400 or r.get("status") in (401, 403, 405):
                    found.append({"url": url, "status": r["status"], "length": len(r["body"]),
                                  "content_type": r["headers"].get("content-type", ""),
                                  "redirect": r.get("final_url") if r.get("final_url") != url else ""})
            evidence_cmd = {"type": "command_output",
                            "command": "httpx GET over built-in path list",
                            "returncode": 0, "paths_tried": len(DEFAULT_PATHS), "stdout": ""}

        if not found:
            ctx.add(unavailable("WEB-03", "Content and path discovery",
                                f"No path returned a reportable status on {target} "
                                f"({engine_used}, {len(words)} candidates)."))
            return
        art = ctx.save_text("web_paths.json", json.dumps(found, indent=2))
        ctx.add(Result(
            "WEB-03", "Content and path discovery", "info",
            description=(f"{len(found)} path(s) returned a reportable status on {target} via "
                         f"{engine_used} (wordlist {len(words)} entries). Statuses: "
                         + ", ".join(sorted({str(f['status']) for f in found}))),
            asset=target, source="live",
            evidence=[evidence_cmd or {"type": "other", "summary": "ffuf run"},
                      {"type": "other", "summary": "discovered paths", "paths": found[:40]},
                      {**art, "type": "file"}],
            data={"engine": engine_used, "wordlist_size": len(words),
                  "paths": found, "wordlist": artifact(wordlist, "web_wordlist.txt")}))

        interesting = [f for f in found if INTERESTING_PATH.search(f["url"])]
        if interesting:
            ctx.add(Result(
                "WEB-03b", "Potentially sensitive path reachable", "info", severity="low",
                description="; ".join(f"{f['url']} -> HTTP {f['status']} ({f['length']} B)"
                                      for f in interesting[:10]),
                asset=target, source="live",
                remediation=("Restrict administrative/debug paths to authenticated users and "
                             "remove VCS artefacts such as .git/ from the document root."),
                evidence=[{"type": "other", "summary": "sensitive paths", "paths": interesting[:20]}],
                data={"interesting": interesting[:20]}))

    # ------------------------------------------------------------ WEB-04 -----
    def cookie_flags(self, ctx: Context, targets: list[str]) -> None:
        cookies: list[dict] = []
        sources: list[str] = []
        path = ctx.params.get("cookie_path") or "/"
        for target in targets[:5]:
            url = target.rstrip("/") + (path if path.startswith("/") else "/" + path)
            resp = http_get(url, timeout=float(ctx.params.get("http_timeout", 8)))
            sources.append(f"GET {url} -> {resp.get('status', resp.get('error'))}")
            if not resp.get("ok"):
                continue
            raw_list = resp.get("set_cookie_all") or []
            for raw in raw_list:
                cookies.append(parse_set_cookie(raw, url))
        if not cookies:
            ctx.add(unavailable("WEB-04", "Cookie and session flags",
                                "No Set-Cookie header was returned by the probed path(s), so no "
                                "cookie flags could be assessed. Probes: " + "; ".join(sources)))
            return
        art = ctx.save_text("web_cookies.json", json.dumps(cookies, indent=2))
        weak_secure = [c for c in cookies if c["secure_required"] and not c["secure"]]
        weak_httponly = [c for c in cookies if not c["httponly"]]
        weak_samesite = [c for c in cookies if c["samesite"] in ("", "none")]
        ctx.add(Result(
            "WEB-04", "Cookie and session flags", "info",
            description=(f"{len(cookies)} cookie(s) observed. Not Secure: {len(weak_secure)}; "
                         f"missing HttpOnly: {len(weak_httponly)}; SameSite missing/None: "
                         f"{len(weak_samesite)}."),
            asset=", ".join(targets[:5]), source="live",
            evidence=[{"type": "other", "summary": "parsed Set-Cookie headers",
                       "cookies": cookies, "probes": sources},
                      {**art, "type": "file"}],
            data={"cookies": cookies, "probes": sources}))

        findings = []
        if weak_secure:
            findings.append("missing Secure: " + ", ".join(sorted({c["name"] for c in weak_secure})))
        if weak_httponly:
            findings.append("missing HttpOnly: " + ", ".join(sorted({c["name"] for c in weak_httponly})))
        if weak_samesite:
            findings.append("SameSite missing/None: " + ", ".join(sorted({c["name"] for c in weak_samesite})))
        if findings:
            ctx.add(Result(
                "WEB-04b", "Session cookie flag weakness", "fail", severity="medium",
                description="; ".join(findings),
                asset=", ".join(targets[:5]), source="live", cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe=["CWE-1004", "CWE-614"],
                remediation=("Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session "
                             "cookie, and scope Domain/Path as narrowly as the app allows."),
                evidence=[{"type": "other", "summary": "cookie weaknesses", "findings": findings,
                           "cookies": cookies}],
                data={"findings": findings}))

    # ------------------------------------------------------------ WEB-05 -----
    def cors_probe(self, ctx: Context, targets: list[str]) -> None:
        origin = ctx.params.get("cors_origin") or "https://evil.example"
        rows: list[dict] = []
        for target in targets[:5]:
            control = http_get(target, timeout=float(ctx.params.get("http_timeout", 8)))
            test = http_get(target, timeout=float(ctx.params.get("http_timeout", 8)),
                            extra_headers={"Origin": origin})
            if not test.get("ok"):
                rows.append({"url": target, "error": test.get("error", "no response")})
                continue
            h = {k.lower(): v for k, v in test["headers"].items()}
            ch = {k.lower(): v for k, v in (control.get("headers") or {}).items()}
            rows.append({
                "url": target, "request_origin": origin,
                "status": test["status"],
                "access_control_allow_origin": h.get("access-control-allow-origin", ""),
                "access_control_allow_credentials": h.get("access-control-allow-credentials", ""),
                "access_control_allow_methods": h.get("access-control-allow-methods", ""),
                "access_control_expose_headers": h.get("access-control-expose-headers", ""),
                "access_control_max_age": h.get("access-control-max-age", ""),
                "vary": h.get("vary", ""),
                "without_origin_acao": ch.get("access-control-allow-origin", ""),
            })
        good = [r for r in rows if "error" not in r]
        if not good:
            ctx.add(unavailable("WEB-05", "CORS policy probe",
                                "No target answered the Origin-bearing request: " +
                                "; ".join(f"{r['url']}: {r['error']}" for r in rows[:5])))
            return
        art = ctx.save_text("web_cors.json", json.dumps(rows, indent=2))
        ctx.add(Result(
            "WEB-05", "CORS policy probe", "info",
            description="; ".join(
                f"{r['url']}: ACAO={r['access_control_allow_origin'] or '(none)'} "
                f"ACAC={r['access_control_allow_credentials'] or '(none)'}" for r in good[:5]),
            asset=", ".join(r["url"] for r in good), source="live",
            evidence=[{"type": "other", "summary": "CORS response headers",
                       "origin_sent": origin, "rows": good},
                      {**art, "type": "file"}],
            data={"origin": origin, "rows": rows}))

        reflected = [r for r in good if r["access_control_allow_origin"] == origin]
        wildcard = [r for r in good if r["access_control_allow_origin"] == "*"]
        if reflected:
            creds = [r for r in reflected if r["access_control_allow_credentials"].lower() == "true"]
            ctx.add(Result(
                "WEB-05b", "Arbitrary Origin reflected in Access-Control-Allow-Origin",
                "fail", severity="high" if creds else "medium",
                description=("The supplied arbitrary origin was echoed back: "
                             + "; ".join(f"{r['url']} -> ACAO={r['access_control_allow_origin']}, "
                                         f"ACAC={r['access_control_allow_credentials'] or '(none)'}"
                                         for r in reflected[:5])
                             + (" With credentials enabled any origin can read authenticated "
                                "responses." if creds else
                                " Without credentials only unauthenticated data is readable.")),
                asset=", ".join(r["url"] for r in reflected), source="live",
                cvss_score=8.1 if creds else 5.3,
                cvss_vector=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N" if creds
                             else "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
                cwe=["CWE-942"],
                remediation=("Replace origin reflection with a strict allow-list, and never "
                             "combine a wildcard/reflected origin with "
                             "Access-Control-Allow-Credentials: true."),
                evidence=[{"type": "other", "summary": "reflected origins", "rows": reflected}],
                data={"reflected": reflected, "credentials": bool(creds)}))
        elif wildcard:
            ctx.add(Result(
                "WEB-05c", "Wildcard Access-Control-Allow-Origin", "info", severity="low",
                description="ACAO=* returned for: " + ", ".join(r["url"] for r in wildcard[:5]),
                asset=", ".join(r["url"] for r in wildcard), source="live", cwe=["CWE-942"],
                remediation="Scope ACAO to the specific front-end origins that need access.",
                evidence=[{"type": "other", "summary": "wildcard rows", "rows": wildcard}],
                data={"wildcard": wildcard}))

    # ------------------------------------------------------------ WEB-06 -----
    def info_disclosure(self, ctx: Context, targets: list[str]) -> None:
        extra = ctx.params.get("disclosure_paths") or []
        candidates = list(dict.fromkeys(["/robots.txt", "/.git/HEAD", "/server-status",
                                        "/phpinfo.php", "/.env", "/crossdomain.xml",
                                        "/nonexistent-wd-probe-404"] + [str(p) for p in extra]))
        target = targets[0]
        rows: list[dict] = []
        for path in candidates:
            url = target.rstrip("/") + path
            resp = http_get(url, timeout=float(ctx.params.get("http_timeout", 8)), read_body=True)
            if not resp.get("ok"):
                rows.append({"url": url, "error": resp.get("error", "")})
                continue
            body = resp["body"]
            markers = [m for m in STACK_TRACE_MARKERS + INFO_DISCLOSURE_MARKERS if m in body]
            rows.append({"url": url, "status": resp["status"], "length": len(body),
                         "content_type": resp["headers"].get("content-type", ""),
                         "markers": markers,
                         "baseline_404": path.endswith("404"),
                         "preview": body[:400].replace("\n", " ")})
        if not any(r.get("status") for r in rows):
            ctx.add(unavailable("WEB-06", "Information disclosure",
                                f"No disclosure path answered on {target}."))
            return
        # The 404 probe sets the baseline: a soft-404 makes every other "hit" noise.
        baseline = next((r for r in rows if r.get("baseline_404")), {})
        soft404 = baseline.get("status") == 200
        hits = [r for r in rows if r.get("status") in (200, 301, 401, 403)
                and not r.get("baseline_404")]
        art = ctx.save_text("web_disclosure.json", json.dumps(rows, indent=2))
        ctx.add(Result(
            "WEB-06", "Information disclosure", "info",
            description=(f"{len(hits)} path(s) responded on {target}"
                         + (f"; the 404 baseline returned HTTP {baseline.get('status')} "
                            f"({baseline.get('length')} B) so the origin may use a soft-404"
                            if soft404 else "")
                         + ". Only observed responses are listed."),
            asset=target, source="live",
            evidence=[{"type": "other", "summary": "disclosure probe rows", "rows": rows},
                      {**art, "type": "file"}],
            data={"rows": rows, "soft_404": soft404, "baseline": baseline}))

        notable = [r for r in hits if r.get("markers") or r["url"].endswith(
            ("robots.txt", ".env", ".git/HEAD", "server-status", "phpinfo.php"))]
        if notable:
            ctx.add(Result(
                "WEB-06b", "Responding information-disclosure path", "info", severity="low",
                description="; ".join(f"{r['url']} -> HTTP {r['status']} ({r['length']} B)"
                                      + (f" markers={r['markers'][:3]}" if r.get("markers") else "")
                                      for r in notable[:10]),
                asset=target, source="live",
                remediation=("Remove VCS metadata and environment files from the document root, "
                             "restrict /server-status and phpinfo to localhost, and disable "
                             "verbose error pages in production."),
                evidence=[{"type": "other", "summary": "notable disclosure responses",
                           "rows": notable[:15]}],
                data={"notable": notable[:15]}))
        traces = [r for r in hits if any(m in r["markers"] for m in STACK_TRACE_MARKERS)]
        if traces:
            ctx.add(Result(
                "WEB-06c", "Stack trace or framework error exposed", "fail", severity="medium",
                description="; ".join(f"{r['url']}: {', '.join(r['markers'][:3])}" for r in traces[:5]),
                asset=target, source="live", cvss_score=5.3, cwe=["CWE-209"],
                remediation="Return generic error pages in production and log details server-side.",
                evidence=[{"type": "other", "summary": "trace responses", "rows": traces[:10]}],
                data={"traces": traces[:10]}))

    # ------------------------------------------------------------ WEB-07 -----
    def reflection(self, ctx: Context, targets: list[str]) -> None:
        token = "WDref" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        param = ctx.params.get("reflect_param") or "q"
        paths = ctx.params.get("reflect_paths") or ["/", "/search", "/index.php", "/api"]
        rows: list[dict] = []
        for target in targets[:3]:
            for path in paths:
                url = target.rstrip("/") + path
                sep = "&" if "?" in url else "?"
                probe = f"{url}{sep}{param}={token}"
                control = http_get(url, timeout=float(ctx.params.get("http_timeout", 8)),
                                   read_body=True)
                resp = http_get(probe, timeout=float(ctx.params.get("http_timeout", 8)),
                                read_body=True)
                row = {"url": url, "probe": probe, "param": param, "token": token,
                       "status": resp.get("status"), "control_status": control.get("status")}
                if resp.get("ok"):
                    body = resp["body"]
                    row["reflected"] = token in body
                    row["reflection_count"] = body.count(token)
                    row["control_had_token"] = token in control.get("body", "")
                    # Where it landed tells the next tester which context to attack.
                    idx = body.find(token)
                    row["context"] = (body[max(0, idx - 60):idx + len(token) + 60]
                                      .replace("\n", " ") if idx >= 0 else "")
                    row["in_attribute"] = bool(idx >= 0 and re.search(
                        r"(href|src|value|action)\s*=\s*[\"'][^\"']*$",
                        body[max(0, idx - 200):idx]))
                    row["in_script"] = bool(idx >= 0 and body.rfind("<script", 0, idx)
                                            > body.rfind("</script>", 0, idx))
                rows.append(row)
        if not any(r.get("status") for r in rows):
            ctx.add(unavailable("WEB-07", "Injection-surface indicators (reflection)",
                                "No endpoint answered the reflection probe: " +
                                "; ".join(r["probe"] for r in rows[:3])))
            return
        art = ctx.save_text("web_reflection.json", json.dumps(rows, indent=2))
        echoed = [r for r in rows if r.get("reflected")]
        ctx.add(Result(
            "WEB-07", "Injection-surface indicators (reflection)", "info",
            description=(f"Sent a unique benign marker ({token}) as ?{param}= to "
                         f"{len(rows)} endpoint(s); {len(echoed)} reflected it verbatim. "
                         "Verbatim reflection is a candidate surface only - it is NOT a claim of XSS."),
            asset=", ".join(targets[:3]), source="live",
            evidence=[{"type": "other", "summary": "reflection rows", "rows": rows},
                      {**art, "type": "file"}],
            data={"token": token, "param": param, "rows": rows, "reflected": len(echoed)}))
        if echoed:
            ctx.add(Result(
                "WEB-07b", "Parameter value echoed into the response body", "info", severity="low",
                description="; ".join(
                    f"{r['url']} reflects ?{param}= verbatim "
                    f"({r['reflection_count']}x, in_attribute={r['in_attribute']}, "
                    f"in_script={r['in_script']}, context=\"{r['context'][:70]}\")"
                    for r in echoed[:5]),
                asset=", ".join(r["url"] for r in echoed[:5]), source="live", cwe=["CWE-79"],
                remediation=("Encode reflected values for their output context and validate on the "
                             "server. Confirm exploitability with a context-specific payload before "
                             "reporting XSS."),
                evidence=[{"type": "other", "summary": "reflected endpoints", "rows": echoed}],
                data={"reflected": echoed}))

    # ------------------------------------------------------------ WEB-08 -----
    def nuclei_baseline(self, ctx: Context, targets: list[str]) -> None:
        if not have("nuclei"):
            ctx.add(unavailable("WEB-08", "Nuclei baseline scan",
                                "nuclei is not installed on this host."))
            return
        target = targets[0]
        out = ctx.path("nuclei_web.jsonl")
        tmpl = ctx.params.get("nuclei_template")
        defaults = ["/root/nuclei-templates/http/technologies/tech-detect.yaml",
                    os.path.expanduser("~/nuclei-templates/http/technologies/tech-detect.yaml")]
        if not tmpl:
            tmpl = next((p for p in defaults if os.path.exists(p)), "")
        argv = ["nuclei", "-u", target, "-jsonl", "-o", out, "-rl", "20", "-c", "5",
                "-timeout", "5", "-retries", "0", "-silent", "-nc", "-disable-update-check"]
        if tmpl:
            argv += ["-t", str(tmpl)]
        else:
            argv += ["-tags", str(ctx.params.get("nuclei_tags", "tech"))]
        argv += ["-severity", str(ctx.params.get("nuclei_severity", "info,low,medium"))]
        budget = int(ctx.params.get("nuclei_timeout", 60))
        started = time.time()
        res = runner.run(argv, timeout=budget)
        elapsed = round(time.time() - started, 1)
        findings = parse_nuclei_jsonl(out)
        art = artifact(out, "nuclei_web.jsonl", "jsonl") if os.path.exists(out) else None
        evidence = [res.as_evidence(),
                    {"type": "other", "summary": "parsed nuclei findings",
                     "findings": findings[:40]}]
        if art:
            evidence.append({**art, "type": "file"})

        if not findings:
            ctx.add(Result(
                "WEB-08", "Nuclei baseline scan", "info",
                description=(f"nuclei produced no finding for {target} in {elapsed}s "
                             f"(template={'/'.join(str(tmpl).split('/')[-2:]) if tmpl else 'tags=' + str(ctx.params.get('nuclei_tags', 'tech'))}, "
                             f"timeout={budget}s, timed_out={res.timed_out}). An empty baseline is "
                             "not evidence of a clean target."),
                asset=target, source="live", evidence=evidence,
                data={"findings": [], "elapsed_s": elapsed, "argv": argv,
                      "returncode": res.returncode, "timed_out": res.timed_out}))
            return
        ctx.add(Result(
            "WEB-08", "Nuclei baseline scan", "info",
            description=(f"nuclei reported {len(findings)} finding(s) on {target} in {elapsed}s: "
                         + "; ".join(f"{f['template']}"
                                     f"{'[' + f['matcher'] + ']' if f['matcher'] else ''}"
                                     f" ({f['severity']})" for f in findings[:8])),
            asset=target, source="live", evidence=evidence,
            data={"findings": findings, "elapsed_s": elapsed, "argv": argv,
                  "returncode": res.returncode, "timed_out": res.timed_out}))
        # Only non-informational severities are escalated as findings.
        serious = [f for f in findings if f["severity"] in ("critical", "high", "medium", "low")]
        if serious:
            ctx.add(Result(
                "WEB-08b", "Nuclei template matched a reportable severity", "fail",
                severity=serious[0]["severity"],
                description="; ".join(f"{f['template']} -> {f['matched_at']} ({f['name']})"
                                      for f in serious[:8]),
                asset=target, source="live",
                remediation="Review each matched template's request/response in the saved JSONL "
                            "and remediate per the template's own recommendation.",
                evidence=[{"type": "other", "summary": "reportable nuclei findings",
                           "findings": serious[:20]}],
                data={"serious": serious[:20]}))


# ================================================================ transport ==
def normalise_target(target: str) -> str:
    t = str(target).strip()
    if not t:
        return t
    if not t.startswith(("http://", "https://")):
        host, port = parse_host_port(t)
        scheme = "https" if port in (443, 8443) else "http"
        t = f"{scheme}://{t}"
    return t.rstrip("/") or t


def cipher_bits(host: str, port: int) -> int | None:
    """Negotiated cipher strength, read from a fresh unverified handshake."""
    import ssl
    try:
        ctx = ssl._create_unverified_context()
        with __import__("socket").create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                return s.cipher()[2] if s.cipher() else None
    except OSError:
        return None


def http_get(url: str, timeout: float = 8.0, extra_headers: dict | None = None,
             read_body: bool = True) -> dict:
    """One real GET with the browser-like client. Returns a normalised record."""
    started = time.time()
    try:
        import httpx
    except Exception as exc:
        return {"ok": False, "error": f"httpx not importable: {type(exc).__name__}"}
    headers = {"User-Agent": "WD-CYBER-TOOLKIT-NEO/webapp (+assessment)",
               "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=True,
                          headers=headers) as client:
            r = client.get(url)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    body = r.text if read_body else ""
    return {
        "ok": True, "status": r.status_code,
        "headers": dict(r.headers),
        "set_cookie_all": r.headers.get_list("set-cookie"),
        "body": body[:200000],
        "body_sha256": __import__("hashlib").sha256(body.encode("utf-8", "replace")).hexdigest(),
        "final_url": str(r.url),
        "redirects": [str(h.url) for h in r.history],
        "elapsed_s": round(time.time() - started, 3),
    }


def parse_set_cookie(raw: str, url: str) -> dict:
    """Parse one Set-Cookie header into name + explicit flag observations."""
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=") if parts else ("", "", "")
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    is_https = url.startswith("https://")
    return {
        "url": url, "name": name.strip(), "value_length": len(value),
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": attrs.get("samesite", ""),
        "domain": attrs.get("domain", ""),
        "path": attrs.get("path", ""),
        "max_age": attrs.get("max-age", ""),
        "expires": attrs.get("expires", ""),
        "secure_required": is_https,
        "raw": raw[:300],
    }


def parse_ffuf(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []
    out = []
    for r in doc.get("results") or []:
        out.append({"url": r.get("url", ""), "status": r.get("status"),
                    "length": r.get("length"), "words": r.get("words"),
                    "content_type": r.get("content-type", "") or r.get("content_type", ""),
                    "redirect": r.get("redirectlocation", "")})
    return out


def parse_nuclei_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
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
            info = ev.get("info") or {}
            out.append({
                "template": ev.get("template-id", ""),
                "name": info.get("name", ""),
                "severity": str(info.get("severity", "info")).lower(),
                "matcher": ev.get("matcher-name", ""),
                "matched_at": ev.get("matched-at", ""),
                "type": ev.get("type", ""),
                "tags": info.get("tags", []),
                "curl": ev.get("curl-command", ""),
            })
    return out
