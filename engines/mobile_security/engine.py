"""Module F - Mobile & Zero-Click Security.

Real work only: when an APK/IPA artifact is supplied its manifest, permissions,
components, deeplink routes and signing facts are parsed from the bytes with
pure standard-library Python (a hand-written Android binary-XML reader, a
plist reader and a Mach-O header reader).  When no artifact is supplied the
engine inspects this host's mobile-adjacent surface for real (getprop/adb if
they exist, platform version, package-manager security updates) and states the
exact reason when a mobile platform is simply not present.

Exposure statements (MOB-06) are derived from observed version facts and are
labelled as exposure *classes*, never as confirmed exploits.
"""
from __future__ import annotations

import json
import os
import platform
import plistlib
import re
import struct
import zipfile
from importlib import metadata as importlib_metadata
from typing import Any

from backend import runner
from engines.base import Context, Result, have, sha256_file, unavailable

# ---------------------------------------------------------------------------
# Android attribute resource-id fallbacks.  Applied only when the string pool
# carries no name for an attribute (common in obfuscated/optimised manifests).
# The first block is confirmed from a real AXML dump produced by this parser.
# ---------------------------------------------------------------------------
ANDROID_ATTR_IDS: dict[int, str] = {
    0x01010001: "label", 0x01010002: "icon", 0x01010003: "name",
    0x01010006: "permission", 0x0101000e: "enabled", 0x0101000f: "debuggable",
    0x01010010: "exported", 0x01010011: "process", 0x0101001d: "launchMode",
    0x01010026: "mimeType", 0x01010027: "scheme", 0x01010028: "host",
    0x01010029: "port", 0x0101002a: "path", 0x0101002b: "pathPrefix",
    0x0101002c: "pathPattern", 0x0101020c: "minSdkVersion",
    0x0101021b: "versionCode", 0x0101021c: "versionName",
    0x01010270: "targetSdkVersion", 0x01010271: "maxSdkVersion",
    0x01010280: "allowBackup", 0x010104ec: "usesCleartextTraffic",
    0x01010527: "usesCleartextTraffic",
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Android "dangerous" (runtime-prompt) permissions that matter for an audit.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE", "android.permission.BODY_SENSORS",
    "android.permission.GET_ACCOUNTS", "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR", "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT",
    "android.permission.POST_NOTIFICATIONS", "android.permission.NEARBY_WIFI_DEVICES",
}

# Permissions that grant unusually powerful capability when present.
POWERFUL_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW": "draws over other apps (overlay/phishing primitive)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility service can read and act on all UI",
    "android.permission.INSTALL_PACKAGES": "silent APK installation (platform/privileged)",
    "android.permission.DELETE_PACKAGES": "silent APK removal (platform/privileged)",
    "android.permission.PACKAGE_USAGE_STATS": "app-usage surveillance",
    "android.permission.REQUEST_INSTALL_PACKAGES": "can prompt to sideload APKs",
    "android.permission.READ_LOGS": "reads system log buffers",
    "android.permission.DUMP": "reads service dumps",
    "android.permission.WRITE_SECURE_SETTINGS": "modifies secure settings",
    "android.permission.CHANGE_CONFIGURATION": "changes global configuration",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "mounts filesystems",
    "android.permission.CAPTURE_AUDIO_OUTPUT": "captures audio output",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "all-files access",
    "android.permission.QUERY_ALL_PACKAGES": "sees every installed package",
}

# In-code table of pinned versions with a known-vulnerable range.  Deliberately
# small and conservative; every hit is reported as "candidate, verify upstream"
# unless the range is a textbook case, and the advisory id is always included.
KNOWN_VULN = [
    ("log4j-core", "<2.15.0", "CVE-2021-44228", "critical", "JNDI lookup remote code execution (Log4Shell)"),
    ("lodash", "<4.17.21", "CVE-2021-23337", "high", "template command injection"),
    ("minimist", "<1.2.6", "CVE-2021-44906", "high", "prototype pollution"),
    ("axios", "<0.21.2", "CVE-2021-3749", "high", "regular-expression denial of service"),
    ("pyyaml", "<5.4", "CVE-2020-1747", "high", "arbitrary code execution via full_load"),
    ("jinja2", "<2.11.3", "CVE-2020-28493", "medium", "regular-expression denial of service"),
    ("requests", "<2.20.0", "CVE-2018-18074", "high", "authorization header leaked on redirect"),
    ("urllib3", "<1.26.5", "CVE-2021-33503", "high", "regular-expression denial of service"),
    ("django", "<2.2.28", "CVE-2022-28346", "critical", "SQL injection in QuerySet.annotate"),
    ("pillow", "<9.0.1", "CVE-2022-22817", "high", "arbitrary expression evaluation in ImageMath"),
    ("cryptography", "<3.3.2", "CVE-2020-36242", "high", "buffer overflow in symmetric decryption"),
    ("numpy", "<1.22.0", "CVE-2021-41496", "medium", "buffer overflow in array conversion"),
    ("guava", "<32.0.0", "CVE-2023-2976", "medium", "temp-directory information disclosure"),
    ("commons-text", "<1.10.0", "CVE-2022-42889", "critical", "interpolator remote code execution (Text4Shell)"),
    ("spring-core", "<5.3.18", "CVE-2022-22965", "critical", "data-binding remote code execution (Spring4Shell)"),
    ("struts2-core", "<2.5.30", "CVE-2021-31805", "critical", "OGNL double evaluation remote code execution"),
    ("commons-collections", "<3.2.2", "CVE-2015-6420", "high", "unsafe Java deserialization"),
    ("okhttp", "<3.12.13", "CVE-2021-0341", "medium", "certificate pinning bypass via hostname verification"),
]

# targetSdk -> exposure classes actually introduced/changed at that API level.
TARGET_SDK_EXPOSURES = [
    (31, 31, "Missing FLAG_IMMUTABLE/FLAG_MUTABLE enforcement for PendingIntent (API 31+: an implicit-mutable "
             "PendingIntent can be filled in by another app)."),
    (30, 30, "No package-visibility filtering by default (API 30 also enforces scoped storage and "
             "requires explicit <queries>)."),
    (29, 29, "No enforced scoped storage; legacy all-files access remains possible on API 29 targets."),
    (28, 28, "Cleartext HTTP is allowed by default (usesCleartextTraffic default true below API 28)."),
    (26, 26, "No background-execution limits / implicit-broadcast restrictions introduced at API 26."),
    (23, 23, "Runtime permission model absent (API 23+ introduces per-permission grants)."),
]


class MobileEngine:
    module = "mobile_security"
    title = "Module F - Mobile & Zero-Click Security"
    description = ("APK/IPA static analysis from the artifact bytes (binary AndroidManifest, permissions, "
                   "exported components, deeplinks, signing facts, Mach-O header), platform patch level, "
                   "dependency review, configuration audit and risk prioritisation.")
    checks = [
        ("MOB-01", "Application inventory", True),
        ("MOB-02", "OS patch / platform version verification", True),
        ("MOB-03", "Permission auditing", True),
        ("MOB-04", "Attack surface inventory (exported components, deeplinks)", True),
        ("MOB-05", "Dependency vulnerability checks", True),
        ("MOB-06", "Known exploit exposure assessment", True),
        ("MOB-07", "Secure configuration auditing", True),
        ("MOB-08", "Vulnerability prioritisation", True),
    ]

    # ------------------------------------------------------------- dispatch --
    def run(self, ctx: Context) -> list[Result]:
        self._art: dict[str, Any] = {}
        self._source = "lab" if (ctx.mode == "lab" or ctx.params.get("fixture")) else "live"
        steps = [("MOB-01", self.application_inventory), ("MOB-02", self.platform_patch),
                 ("MOB-03", self.permission_audit), ("MOB-04", self.attack_surface),
                 ("MOB-05", self.dependency_checks), ("MOB-06", self.exploit_exposure),
                 ("MOB-07", self.config_audit), ("MOB-08", self.prioritisation)]
        for i, (cid, fn) in enumerate(steps):
            if runner.executor.stopped():
                ctx.add(Result("MOB-STOP", "Execution halted by emergency stop", "error",
                               description="Remaining mobile checks were not executed.", source="local"))
                break
            try:
                fn(ctx)
            except Exception as exc:
                ctx.add(Result(f"{cid}-ERR", "Check raised an exception", "error",
                               description=f"{type(exc).__name__}: {exc}", source="local"))
            ctx.progress(int((i + 1) / len(steps) * 100))
        return ctx.findings

    # ------------------------------------------------------------ MOB-01 ----
    def application_inventory(self, ctx: Context) -> None:
        apk = ctx.params.get("apk_path")
        ipa = ctx.params.get("ipa_path")
        art = apk or ipa
        host = self._host_mobile_facts()
        self._art = {"host": host, "kind": None}

        if art:
            if not os.path.exists(str(art)):
                ctx.add(unavailable("MOB-01", "Application inventory",
                                    f"params.apk_path/ipa_path was supplied but does not exist: {art}", asset=str(art)))
                self._no_artifact_reason = f"artifact path not found: {art}"
                return
            try:
                if str(art).lower().endswith(".ipa"):
                    info = analyse_ipa(str(art))
                else:
                    info = analyse_apk(str(art))
            except Exception as exc:
                ctx.add(unavailable("MOB-01", "Application inventory",
                                    f"Artifact could not be parsed as an APK/IPA: {type(exc).__name__}: {exc}",
                                    asset=os.path.basename(str(art))))
                self._no_artifact_reason = f"unparseable artifact: {exc}"
                return
            self._art.update(info)
            self._art["kind"] = info["kind"]
            man = info.get("manifest") or {}
            desc = (f"Inspected {info['kind'].upper()} {os.path.basename(info['path'])} "
                    f"({info['size']:,} bytes, sha256 {info['sha256'][:16]}...): "
                    f"package={man.get('package') or info.get('bundle_id') or 'unknown'}, "
                    f"versionName={man.get('versionName') or info.get('bundle_version') or 'n/a'}, "
                    f"versionCode={man.get('versionCode', 'n/a')}.")
            ctx.add(Result(
                "MOB-01", "Application inventory", "info", description=desc,
                asset=man.get("package") or info.get("bundle_id") or os.path.basename(info["path"]),
                source=self._source,
                evidence=[{"type": "other", "summary": f"{info['kind']} inventory", "inventory": {
                    k: v for k, v in info.items() if k not in ("manifest", "plist", "dex", "macho")}},
                    {"type": "other", "summary": "host mobile facts", "host": host}],
                data={"inventory": {k: v for k, v in info.items()
                                    if k not in ("manifest", "plist", "macho", "signer")},
                      "manifest_summary": summarise_manifest(info.get("manifest")),
                      "plist": info.get("plist"), "macho": info.get("macho"),
                      "signer": info.get("signer"), "host": host}))
            return

        # ---- no artifact: inspect the host for a genuine mobile platform ----
        reasons = []
        if not host["getprop"]["present"]:
            reasons.append("`getprop` is not in PATH (no Android runtime on this host)")
        if not host["system_build_prop"]["present"]:
            reasons.append("/system/build.prop does not exist")
        if not host["adb"]["present"]:
            reasons.append("`adb` is not installed, so no attached device could be inventoried")
        if not host["android_markers"]:
            reasons.append("no Android markers found (/system, ro.build.version.*, /data/app)")
        reason = ("No APK/IPA artifact supplied (params.apk_path / params.ipa_path) and this host is not an "
                  "Android device: " + "; ".join(reasons) +
                  f". Host platform observed instead: {host['uname']}")
        self._no_artifact_reason = reason
        ctx.add(Result(
            "MOB-01", "Application inventory", "unavailable", description=reason,
            asset=host.get("hostname", ""), source="unavailable",
            evidence=[{"type": "other", "summary": reason},
                      {"type": "other", "summary": "host facts", "host": host}],
            data={"host": host, "expected_params": ["apk_path", "ipa_path"]}))

    # ------------------------------------------------------------ MOB-02 ----
    def platform_patch(self, ctx: Context) -> None:
        host = self._art.get("host") or self._host_mobile_facts()
        man = (self._art.get("manifest") or {})
        osr = host.get("os_release") or {}
        rows: list[dict] = []
        evidence: list[dict] = []

        # --- real platform identity -----------------------------------------
        if host["getprop"]["present"]:
            props = host["getprop"]["values"]
            rows.append({"platform": "android", "source": "getprop",
                         "release": props.get("ro.build.version.release"),
                         "sdk": props.get("ro.build.version.sdk"),
                         "security_patch": props.get("ro.build.version.security_patch"),
                         "fingerprint": props.get("ro.build.fingerprint")})
        uname = host.get("uname", "")
        kernel = (uname.split(" ")[2] if len(uname.split(" ")) > 2 else "")
        rows.append({"platform": "host", "source": "uname -a", "uname": uname, "kernel": kernel,
                     "distro": osr.get("PRETTY_NAME"), "distro_version": osr.get("VERSION_ID"),
                     "python": platform.python_version(), "machine": platform.machine()})

        # --- real patch/update counts from the package manager ---------------
        sec = self._apt_security_counts()
        evidence.append({"type": "command_output", "command": sec["command"], "returncode": sec["returncode"],
                         "stdout": sec["tail"], "stderr": sec["stderr"]})

        # --- app-level platform targets from the manifest ---------------------
        targets = {"min_sdk": man.get("min_sdk"), "target_sdk": man.get("target_sdk")}

        if self._art.get("kind"):
            desc = (f"Artifact declares minSdk={targets['min_sdk'] if targets['min_sdk'] is not None else 'absent'} "
                    f"targetSdk={targets['target_sdk'] if targets['target_sdk'] is not None else 'absent'}. "
                    f"Host kernel {kernel or 'unknown'} on {osr.get('PRETTY_NAME', platform.system())}; "
                    f"{sec['security_total']} package(s) upgradable from the security pocket "
                    f"({sec['upgradable_total']} upgradable in total).")
            ctx.add(Result("MOB-02", "OS patch / platform version verification", "info",
                           description=desc, asset=man.get("package", ""), source=self._source,
                           remediation=("Verify the device's real SPL (ro.build.version.security_patch) is current; "
                                        f"the artifact targets API {targets['target_sdk']}."),
                           evidence=evidence, data={"host": rows, "package_manager": sec,
                                                    "app_targets": targets}))
            if sec["security_total"]:
                ctx.add(Result("MOB-02b", "Security-pocket updates pending on the analysis host", "fail",
                               severity="low",
                               description=(f"{sec['security_total']} package(s) on this host resolve from a "
                                            f"security pocket: " + ", ".join(sec["security_packages"][:12])),
                               asset=host.get("hostname", ""), source="local", cvss_score=4.0,
                               cwe=["CWE-1104"],
                               remediation="Apply pending security updates on the host running the assessment.",
                               evidence=[{"type": "command_output", "command": sec["command"],
                                          "stdout": sec["tail"]}],
                               data={"security_packages": sec["security_packages"]}))
        else:
            desc = (f"No mobile platform could be inspected ({self._no_artifact_reason}). Host facts verified "
                    f"instead: {osr.get('PRETTY_NAME', platform.system())} kernel {kernel or 'unknown'}, "
                    f"python {platform.python_version()}, {sec['security_total']} security-pocket update(s) "
                    f"pending of {sec['upgradable_total']} upgradable package(s).")
            ctx.add(Result("MOB-02", "OS patch / platform version verification",
                           "fail" if sec["security_total"] else "info",
                           severity="low" if sec["security_total"] else "info",
                           description=desc, asset=host.get("hostname", ""), source="local",
                           cvss_score=4.0 if sec["security_total"] else None,
                           cwe=["CWE-1104"] if sec["security_total"] else [],
                           remediation="Apply pending security updates on the assessment host.",
                           evidence=evidence, data={"host": rows, "package_manager": sec,
                                                    "app_targets": targets}))
            if sec["security_total"]:
                ctx.add(Result("MOB-02b", "Security-pocket updates pending on this host", "fail", severity="low",
                               description=f"{sec['security_total']} package(s) resolve from an Ubuntu/Security or "
                                           f"-security pocket: " + ", ".join(sec["security_packages"][:12]),
                               asset=host.get("hostname", ""), source="local", cvss_score=4.0,
                               cwe=["CWE-1104"],
                               remediation="Schedule patch deployment; track the security pocket explicitly.",
                               evidence=[{"type": "command_output", "command": sec["command"],
                                          "stdout": sec["tail"]}],
                               data={"security_packages": sec["security_packages"]}))

    # ------------------------------------------------------------ MOB-03 ----
    def permission_audit(self, ctx: Context) -> None:
        man = self._art.get("manifest") or {}
        if not self._art.get("kind"):
            ctx.add(unavailable("MOB-03", "Permission auditing",
                                f"No manifest to audit: {self._no_artifact_reason}"))
            return
        perms = man.get("permissions") or []
        declared = man.get("declared_permissions") or []
        service_perms = man.get("component_permissions") or []
        dangerous = sorted(p for p in perms if p in DANGEROUS_PERMISSIONS)
        powerful = {p: POWERFUL_PERMISSIONS[p] for p in perms if p in POWERFUL_PERMISSIONS}
        ctx.add(Result(
            "MOB-03", "Permission auditing", "info",
            description=(f"{len(perms)} uses-permission declaration(s) parsed from the real manifest; "
                         f"{len(dangerous)} runtime-dangerous, {len(powerful)} powerful; "
                         f"{len(declared)} custom permission(s) defined."),
            asset=man.get("package", ""), source=self._source,
            evidence=[{"type": "other", "summary": "permissions from manifest",
                       "permissions": perms, "dangerous": dangerous, "powerful": powerful,
                       "declared": declared, "component_permissions": service_perms}],
            data={"permissions": perms, "dangerous": dangerous, "powerful": powerful,
                  "declared": declared, "component_permissions": service_perms}))

        for title, combo, why, sev, score in [
            ("OTP / SMS interception capability",
             {"android.permission.READ_SMS", "android.permission.INTERNET"}, "reads SMS (the dominant OTP channel) and can exfiltrate it", "high", 7.1),
            ("Continuous audio/video capture capability",
             {"android.permission.RECORD_AUDIO", "android.permission.CAMERA"}, "microphone plus camera access in one package", "medium", 5.6),
            ("Precise location tracking capability",
             {"android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"},
             "precise location plus network egress (background tracking possible if ACCESS_BACKGROUND_LOCATION is also held)",
             "medium", 5.3),
            ("Contact-harvesting capability",
             {"android.permission.READ_CONTACTS", "android.permission.INTERNET"},
             "reads the address book and can upload it", "medium", 5.0),
        ]:
            if combo <= set(perms):
                ctx.add(Result("MOB-03b", title, "info", severity=sev,
                               description=f"Observed permission combination: {', '.join(sorted(combo))} - {why}.",
                               asset=man.get("package", ""), source=self._source,
                               cvss_score=score, cwe=["CWE-250"],
                               remediation="Confirm each permission is functionally required; prefer scoped APIs "
                                           "(SMS Retriever, Photo Picker, one-shot location).",
                               evidence=[{"type": "other", "summary": "combination", "permissions": sorted(combo)}],
                               data={"combination": sorted(combo)}))
        if powerful:
            ctx.add(Result("MOB-03c", "Powerful permissions granted", "info", severity="medium",
                           description="; ".join(f"{p} ({w})" for p, w in powerful.items()),
                           asset=man.get("package", ""), source=self._source, cwe=["CWE-269"],
                           remediation="Justify powerful permissions in the app's threat model; accessibility and "
                                       "overlay permissions are the main UI-hijack primitives.",
                           evidence=[{"type": "other", "summary": "powerful permissions", "powerful": powerful}],
                           data={"powerful": powerful}))

    # ------------------------------------------------------------ MOB-04 ----
    def attack_surface(self, ctx: Context) -> None:
        if not self._art.get("kind"):
            ctx.add(unavailable("MOB-04", "Attack surface inventory",
                                f"No manifest to inventory: {self._no_artifact_reason}"))
            return
        man = self._art.get("manifest") or {}
        comps = man.get("components") or []
        exported = [c for c in comps if c.get("exported") is True]
        deeplinks = man.get("deeplinks") or []
        schemes = sorted({d["scheme"] for d in deeplinks if d.get("scheme")})
        ctx.add(Result(
            "MOB-04", "Attack surface inventory", "info",
            description=(f"{len(comps)} component(s) parsed; {len(exported)} explicitly exported; "
                         f"{len(deeplinks)} deeplink route(s) across {len(schemes)} scheme(s)"
                         + (f" ({', '.join(schemes)})" if schemes else "") + "."),
            asset=man.get("package", ""), source=self._source,
            evidence=[{"type": "other", "summary": "components and routes",
                       "components": comps, "deeplinks": deeplinks,
                       "url_types": man.get("url_types") or []}],
            data={"components": comps, "exported": exported, "deeplinks": deeplinks,
                  "schemes": schemes, "url_types": man.get("url_types") or []}))

        risky = [c for c in exported if not c.get("permission")]
        if risky:
            listing = "; ".join(f"{c['kind']} {c['name']}" for c in risky[:12])
            ctx.add(Result("MOB-04b", "Exported components without a permission guard", "fail",
                           severity="medium" if len(risky) < 6 else "high",
                           description=(f"{len(risky)} exported component(s) declare no android:permission, so any "
                                        f"installed app can invoke them: {listing}"),
                           asset=man.get("package", ""), source=self._source, cvss_score=6.5 if len(risky) >= 6 else 5.3,
                           cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                           cwe=["CWE-926"], remediation="Set android:exported=false or guard with a signature-level "
                                                       "android:permission on every component that need not be public.",
                           evidence=[{"type": "other", "summary": "exposed components", "components": risky[:30]}],
                           data={"unprotected_exported": risky[:30]}))
        browsable = [d for d in deeplinks if d.get("browsable")]
        if browsable:
            ctx.add(Result("MOB-04c", "Browser-reachable deeplink routes", "info", severity="low",
                           description=("Routes claim BROWSABLE + DEFAULT, so any web page or QR code can open them: "
                                        + "; ".join(f"{d.get('scheme')}://{d.get('host') or '*'}{d.get('path') or ''} "
                                                    f"-> {d.get('component')}" for d in browsable[:10])),
                           asset=man.get("package", ""), source=self._source, cwe=["CWE-939"],
                           remediation="Validate every parameter received through a BROWSABLE route and use "
                                       "Android App Links with asset-link verification for web entry points.",
                           evidence=[{"type": "other", "summary": "browsable routes", "routes": browsable[:20]}],
                           data={"browsable_routes": browsable[:20]}))

    # ------------------------------------------------------------ MOB-05 ----
    def dependency_checks(self, ctx: Context) -> None:
        dep_file = ctx.params.get("dependency_file")
        findings: list[dict] = []
        parsed: dict[str, Any] = {}
        evidence: list[dict] = []
        if dep_file:
            if not os.path.exists(str(dep_file)):
                ctx.add(unavailable("MOB-05", "Dependency vulnerability checks",
                                    f"params.dependency_file does not exist: {dep_file}", asset=str(dep_file)))
                return
            parsed = parse_dependency_file(str(dep_file))
            evidence.append({"type": "file", "path": str(dep_file),
                             "summary": f"{parsed.get('format')} with {len(parsed.get('packages', []))} package(s)"})
            findings.extend(match_known_vulns(parsed.get("packages", [])))

        # Installed python distributions on this host, compared to the same table.
        host_dists = installed_python_dists()
        host_hits = match_known_vulns([{"name": n, "version": v} for n, v in host_dists.items()], origin="host")

        if not dep_file:
            ctx.add(Result(
                "MOB-05", "Dependency vulnerability checks", "info",
                description=(f"No params.dependency_file supplied. Enumerated {len(host_dists)} installed python "
                             f"distribution(s) on this host and compared them against the in-code table of "
                             f"{len(KNOWN_VULN)} known-vulnerable ranges: {len(host_hits)} match(es)."),
                asset="host-python", source="local",
                evidence=[{"type": "other", "summary": "installed python distributions",
                           "distributions": dict(sorted(host_dists.items()))},
                          {"type": "other", "summary": "in-code vulnerability table",
                           "table": [{"package": n, "range": r, "advisory": a} for n, r, a, _s, _d in KNOWN_VULN]}],
                data={"table_size": len(KNOWN_VULN), "matches": host_hits,
                      "installed_count": len(host_dists)}))
        else:
            ctx.add(Result(
                "MOB-05", "Dependency vulnerability checks", "info",
                description=(f"Parsed {parsed.get('format')} ({len(parsed.get('packages', []))} package(s)) and "
                             f"compared pinned versions against {len(KNOWN_VULN)} known-vulnerable ranges: "
                             f"{len(findings)} match(es)."),
                asset=os.path.basename(str(dep_file)), source="local", evidence=evidence,
                data={"format": parsed.get("format"), "packages": parsed.get("packages", []),
                      "matches": findings, "host_matches": host_hits}))
        for hit in (findings + host_hits):
            ctx.add(Result("MOB-05b", f"Vulnerable pinned version: {hit['package']} {hit['version']}", "fail",
                           severity=hit["severity"],
                           description=(f"{hit['package']} {hit['version']} falls in the known-vulnerable range "
                                        f"{hit['range']} ({hit['advisory']}: {hit['detail']}). Candidate - verify "
                                        f"against the upstream advisory before reporting."),
                           asset=hit.get("origin", ""), source="local",
                           cvss_score={"critical": 9.8, "high": 7.5, "medium": 5.3}.get(hit["severity"], 5.0),
                           cwe=["CWE-1395"], remediation=f"Upgrade {hit['package']} past {hit['range'][1:]}.",
                           evidence=[{"type": "other", "summary": "version match", "match": hit}],
                           data=hit))

    # ------------------------------------------------------------ MOB-06 ----
    def exploit_exposure(self, ctx: Context) -> None:
        if not self._art.get("kind"):
            ctx.add(unavailable("MOB-06", "Known exploit exposure assessment",
                                f"No mobile platform version observed ({self._no_artifact_reason}); "
                                f"an exposure map needs a real targetSdk/platform version."))
            return
        man = self._art.get("manifest") or {}
        if self._art.get("kind") == "ipa":
            self._exposure_ios(ctx, man)
            return
        sdk = man.get("target_sdk")
        if sdk is None:
            ctx.add(Result("MOB-06", "Known exploit exposure assessment", "info",
                           description="The manifest declares no targetSdkVersion (implicitly the platform default "
                                       "at build time), so no version-keyed exposure class can be stated.",
                           asset=man.get("package", ""), source=self._source,
                           data={"target_sdk": None}))
            return
        try:
            sdk_i = int(sdk)
        except (TypeError, ValueError):
            ctx.add(Result("MOB-06", "Known exploit exposure assessment", "info",
                           description=f"targetSdkVersion could not be read as an integer: {sdk!r}",
                           asset=man.get("package", ""), source=self._source))
            return
        classes = [{"below_api": lvl, "exposure": txt} for below, lvl, txt in TARGET_SDK_EXPOSURES if sdk_i < below]
        # Above the newest threshold nothing below applies.
        classes = [c for c in TARGET_SDK_EXPOSURES if sdk_i < c[0]]
        rows = [{"below_api": lvl, "exposure": txt} for lvl, _x, txt in classes]
        ctx.add(Result(
            "MOB-06", "Known exploit exposure assessment", "info",
            description=(f"Observed targetSdkVersion={sdk_i}. Applying the version-keyed exposure classes below "
                         f"({len(rows)} class(es) apply). These are derived exposure classes, not confirmed exploits."),
            asset=man.get("package", ""), source=self._source,
            evidence=[{"type": "other", "summary": "targetSdk exposure map", "target_sdk": sdk_i, "classes": rows}],
            data={"target_sdk": sdk_i, "classes": rows}))
        if rows:
            sev = "medium" if sdk_i < 31 else "low"
            ctx.add(Result("MOB-06b", "Target SDK below current platform hardening baseline", "fail", severity=sev,
                           description=(f"targetSdkVersion={sdk_i} predates API 31; the following hardening is not "
                                        f"enforced: " + " ".join(r["exposure"] for r in rows)),
                           asset=man.get("package", ""), source=self._source, cvss_score=5.3 if sdk_i < 30 else 4.3,
                           cwe=["CWE-1059"], remediation="Raise targetSdkVersion to the current platform API after "
                                                          "retesting behaviour changes.",
                           evidence=[{"type": "other", "summary": "applies", "classes": rows}],
                           data={"target_sdk": sdk_i, "classes": rows}))

    # ------------------------------------------------ MOB-06 (iOS branch) ----
    def _exposure_ios(self, ctx: Context, man: dict) -> None:
        """iOS exposure classes are keyed on the deployment target, not an Android API level."""
        min_os = man.get("min_sdk")
        app = man.get("application") or {}
        rows: list[dict] = []
        try:
            major = int(str(min_os).split(".")[0])
        except (TypeError, ValueError):
            major = None
        if major is not None:
            if major < 13:
                rows.append({"below_ios": 13, "exposure":
                             "Deployment target below iOS 13: no universal SceneDelegate lifecycle and no "
                             "Sign in with Apple requirement, so the app still supports long-unsupported runtimes "
                             "that no longer receive security fixes."})
            if major < 14:
                rows.append({"below_ios": 14, "exposure":
                             "Deployment target below iOS 14: no local-network privacy prompt, so local-network "
                             "scanning happens without user consent."})
            if major < 17:
                rows.append({"below_ios": 17, "exposure":
                             "Deployment target below iOS 17: does not opt into the newer privacy manifests / "
                             "required-reason API declarations introduced for App Store submissions."})
        ats = app.get("ATS") or {}
        if app.get("usesCleartextTraffic"):
            rows.append({"ats": "NSAllowsArbitraryLoads=true", "exposure":
                         "App Transport Security is globally disabled, so any plaintext HTTP endpoint is reachable "
                         "and interception needs no certificate."})
        ctx.add(Result(
            "MOB-06", "Known exploit exposure assessment", "info",
            description=(f"Observed iOS MinimumOSVersion={min_os}, DTPlatformVersion={man.get('target_sdk')}. "
                         f"Applying the deployment-target exposure classes below ({len(rows)} class(es) apply). "
                         f"These are derived exposure classes, not confirmed exploits; no iOS CVE id is claimed "
                         f"because the exact device/iOS build was not observed."),
            asset=man.get("package") or "", source=self._source,
            evidence=[{"type": "other", "summary": "iOS exposure map",
                       "min_os": min_os, "platform": man.get("target_sdk"),
                       "ats": ats, "classes": rows}],
            data={"min_os": min_os, "platform": man.get("target_sdk"), "classes": rows}))
        if rows:
            ctx.add(Result("MOB-06b", "iOS deployment target / ATS below current hardening baseline", "fail",
                           severity="medium" if major is None or major < 13 else "low",
                           description="; ".join(r["exposure"] for r in rows),
                           asset=man.get("package") or "", source=self._source,
                           cvss_score=5.3 if (app.get("usesCleartextTraffic")) else 3.7,
                           cwe=["CWE-1059"],
                           remediation="Raise the deployment target to a supported iOS major and enable ATS "
                                       "(remove NSAllowsArbitraryLoads or scope it with exception domains).",
                           evidence=[{"type": "other", "summary": "applies", "classes": rows}],
                           data={"classes": rows}))

    # ------------------------------------------------------------ MOB-07 ----
    def config_audit(self, ctx: Context) -> None:
        if not self._art.get("kind"):
            ctx.add(unavailable("MOB-07", "Secure configuration auditing",
                                f"No manifest to audit: {self._no_artifact_reason}"))
            return
        man = self._art.get("manifest") or {}
        app = man.get("application") or {}
        sdk = man.get("target_sdk")
        checks: list[dict] = []

        def add(name, value, verdict, why):
            checks.append({"attribute": name, "observed_value": value, "verdict": verdict, "rationale": why})

        add("android:allowBackup", app.get("allowBackup"),
            "fail" if app.get("allowBackup") in (True, "true") else ("pass" if app.get("allowBackup") in (False, "false") else "info"),
            "allowBackup=true lets adb backup / auto-backup extract app private data on devices without "
            "full-disk-encryption-backed backup controls.")
        add("android:debuggable", app.get("debuggable"),
            "fail" if app.get("debuggable") in (True, "true") else ("pass" if app.get("debuggable") in (False, "false") else "info"),
            "debuggable=true allows run-as shell access to the app sandbox on any device.")
        cleartext = app.get("usesCleartextTraffic")
        if cleartext in (True, "true"):
            verdict, why = "fail", "usesCleartextTraffic=true permits plaintext HTTP."
        elif cleartext in (False, "false"):
            verdict, why = "pass", "usesCleartextTraffic=false forces TLS for all traffic."
        else:
            verdict = "info"
            why = ("usesCleartextTraffic is not declared: the platform default applies "
                   f"(true below API 28, false from API 28) - targetSdk={sdk}.")
        add("android:usesCleartextTraffic", cleartext, verdict, why)
        add("android:networkSecurityConfig", app.get("networkSecurityConfig"),
            "info", "Without a network security config there is no certificate pinning or per-domain cleartext policy.")
        unprotected = [c for c in (man.get("components") or []) if c.get("exported") is True and not c.get("permission")]
        add("exported-without-permission",
            [c["name"] for c in unprotected], "fail" if unprotected else "pass",
            "Exported components with no permission guard are callable by any co-installed app.")
        add("android:testOnly", app.get("testOnly"),
            "fail" if app.get("testOnly") in (True, "true") else "info",
            "testOnly=true marks a development build; such APKs are installable via adb only and are not "
            "a production artifact.")
        add("signing scheme", self._art.get("signing") or {}, "info",
            "v1-only signing is bypassable with the Janus (CVE-2017-13156) and v1 signature-stripping techniques "
            "on older platforms; v2/v3 presence is checked from the APK Signing Block.")

        fails = [c for c in checks if c["verdict"] == "fail"]
        ctx.add(Result(
            "MOB-07", "Secure configuration auditing", "fail" if fails else "info",
            severity="medium" if fails else "info",
            description=(f"{len(checks)} configuration attribute(s) read from the real manifest; "
                         f"{len(fails)} non-secure: " + (", ".join(c["attribute"] for c in fails) or "none") + "."),
            asset=man.get("package", ""), source=self._source,
            cvss_score=5.0 if fails else None, cwe=["CWE-489"] if fails else [],
            remediation="Set allowBackup=false for secret-bearing apps, debug-gable=false in release, "
                        "usesCleartextTraffic=false with a network security config, and export only required components.",
            evidence=[{"type": "other", "summary": "manifest configuration attributes", "checks": checks}],
            data={"checks": checks, "application": app, "target_sdk": sdk}))

    # ------------------------------------------------------------ MOB-08 ----
    def prioritisation(self, ctx: Context) -> None:
        rows: list[dict] = []
        for f in ctx.findings:
            if not f.check_id.startswith("MOB-") or f.check_id == "MOB-08":
                continue
            if f.status not in ("fail",):
                continue
            rows.append({"check_id": f.check_id, "title": f.title, "severity": f.severity,
                         "cvss": f.cvss_score if f.cvss_score is not None else SEV_SCORE.get(f.severity, 0.0),
                         "asset": f.asset, "source": f.source,
                         "rationale": (f.description[:300] + ("..." if len(f.description) > 300 else ""))})
        rows.sort(key=lambda r: (-(r["cvss"] or 0), {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(r["severity"], 4)))
        observed = sum(1 for f in ctx.findings if f.check_id.startswith("MOB-")
                       and f.source in ("live", "local", "lab"))
        unavail = sum(1 for f in ctx.findings if f.check_id.startswith("MOB-") and f.status == "unavailable")
        desc = (f"Prioritised {len(rows)} failing/observable finding(s) by CVSS-ish score. "
                f"{observed} finding(s) derived from real observation, {unavail} check(s) unavailable.")
        if not rows:
            desc += " Nothing scored: the artifact-level checks had no failing observation to rank."
        ctx.add(Result("MOB-08", "Vulnerability prioritisation", "info",
                       description=desc, asset=self._art.get("manifest", {}).get("package", "")
                       if self._art.get("manifest") else "", source=self._source,
                       evidence=[{"type": "other", "summary": "ranked findings", "ranked": rows}],
                       data={"ranked": rows,
                             "scoring": "CVSS v3.1 base score where the check supplied one, else severity map "
                                        "critical=9.5 high=8.0 medium=5.5 low=3.0 info=0.0",
                             "highest": rows[0] if rows else None,
                             "observed_findings": observed, "unavailable_checks": unavail}))

    # ------------------------------------------------------------- helpers --
    def _host_mobile_facts(self) -> dict[str, Any]:
        uname = ""
        r = runner.run(["uname", "-a"], timeout=8)
        if r.ok or r.stdout:
            uname = r.stdout.strip()
        osr: dict[str, str] = {}
        try:
            with open("/etc/os-release", encoding="utf-8") as fh:
                for line in fh:
                    if "=" in line:
                        k, v = line.rstrip("\n").split("=", 1)
                        osr[k] = v.strip().strip('"')
        except OSError:
            pass
        getprop: dict[str, Any] = {"present": have("getprop"), "values": {}}
        if getprop["present"]:
            g = runner.run(["getprop"], timeout=10)
            for line in (g.stdout or "").splitlines():
                m = re.match(r"^\[([^\]]+)\]: \[([^\]]*)\]$", line.strip())
                if m:
                    getprop["values"][m.group(1)] = m.group(2)
        adb = {"present": have("adb"), "devices": []}
        if adb["present"]:
            d = runner.run(["adb", "devices"], timeout=10)
            adb["devices"] = [l.strip() for l in (d.stdout or "").splitlines()[1:] if l.strip()]
        markers = [p for p in ("/system/build.prop", "/system/bin/app_process", "/data/app",
                               "/system/framework/framework-res.apk") if os.path.exists(p)]
        return {"uname": uname, "hostname": platform.node(), "os_release": osr,
                "getprop": getprop, "adb": adb, "android_markers": markers,
                "system_build_prop": {"present": os.path.exists("/system/build.prop"),
                                      "path": "/system/build.prop"}}

    def _apt_security_counts(self) -> dict[str, Any]:
        out = {"command": "apt-get -s upgrade", "returncode": 0, "security_total": 0,
               "security_packages": [], "upgradable_total": 0, "tail": "", "stderr": "",
               "manager": "apt"}
        if not have("apt-get"):
            out.update({"manager": "absent", "command": "apt-get -s upgrade",
                        "stderr": "apt-get is not installed on this host"})
            return out
        r = runner.run(["apt-get", "-s", "upgrade"], timeout=50)
        out["returncode"] = r.returncode
        out["stderr"] = (r.stderr or "")[-600:]
        lines = (r.stdout or "").splitlines()
        out["tail"] = "\n".join(lines[-25:])
        sec_pkgs, total = [], 0
        for line in lines:
            m = re.match(r"^(?:Inst|Conf)\s+(\S+)\s", line)
            if not m:
                continue
            total += 1
            if "-security" in line or "Security:" in line or "security" in line.lower():
                if m.group(1) not in sec_pkgs:
                    sec_pkgs.append(m.group(1))
        out["security_total"] = len(sec_pkgs)
        out["security_packages"] = sec_pkgs[:40]
        out["upgradable_total"] = len({re.match(r"^(?:Inst|Conf)\s+(\S+)", l).group(1)
                                       for l in lines if re.match(r"^(?:Inst|Conf)\s+(\S+)", l)})
        return out


SEV_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}


# ===========================================================================
# Android binary XML reader (AXML) - pure standard library.
# Container layout: XML chunk header, string pool, optional resource map,
# then START_NAMESPACE/START_ELEMENT/END_ELEMENT/END_NAMESPACE chunks.
# ===========================================================================
RES_STRING_POOL = 0x0001
RES_XML_START_NAMESPACE = 0x0100
RES_XML_END_NAMESPACE = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_RESOURCE_MAP = 0x0180
TYPE_REFERENCE, TYPE_STRING, TYPE_INT_DEC = 0x01, 0x03, 0x10
TYPE_INT_HEX, TYPE_INT_BOOLEAN, TYPE_FLOAT = 0x11, 0x12, 0x04


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


class _StringPool:
    def __init__(self, data: bytes, off: int, hsize: int) -> None:
        count = _u32(data, off + 8)
        flags = _u32(data, off + 16)
        strings_start = _u32(data, off + 20)
        self.utf8 = bool(flags & 0x100)
        self.strings: list[str] = []
        base = off + strings_start
        for i in range(count):
            try:
                s_off = _u32(data, off + hsize + i * 4)
            except struct.error:
                break
            p = base + s_off
            try:
                if self.utf8:
                    n = data[p]
                    p += 1
                    if n & 0x80:
                        n = ((n & 0x7F) << 8) | data[p]
                        p += 1
                    m = data[p]
                    p += 1
                    if m & 0x80:
                        m = ((m & 0x7F) << 8) | data[p]
                        p += 1
                    self.strings.append(data[p:p + m].decode("utf-8", "replace"))
                else:
                    n = _u16(data, p)
                    p += 2
                    if n & 0x8000:
                        n = ((n & 0x7FFF) << 16) | _u16(data, p)
                        p += 2
                    self.strings.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
            except (IndexError, struct.error):
                self.strings.append("")

    def get(self, idx: int) -> str | None:
        if idx is None or idx < 0 or idx >= len(self.strings):
            return None
        return self.strings[idx]


def parse_axml(data: bytes) -> dict:
    """Parse Android binary XML into a nested dict tree."""
    if len(data) < 8:
        raise ValueError("AXML too short")
    magic = _u16(data, 0)
    if magic != 0x0003:
        raise ValueError(f"not a binary XML document (magic 0x{magic:04x})")
    total = _u32(data, 4)
    off = _u16(data, 2)
    pool: _StringPool | None = None
    res_map: list[int] = []
    root: dict = {"tag": "#document", "attrs": {}, "children": [], "parent": None}
    cur = root
    while off + 8 <= min(total, len(data)):
        ctype = _u16(data, off)
        chsize = _u16(data, off + 2)
        csize = _u32(data, off + 4)
        if csize == 0:
            break
        if ctype == RES_STRING_POOL:
            pool = _StringPool(data, off, chsize)
        elif ctype == RES_XML_RESOURCE_MAP:
            n = (csize - chsize) // 4
            res_map = [_u32(data, off + chsize + 4 * i) for i in range(n)]
        elif ctype == RES_XML_START_ELEMENT and pool is not None:
            ns_idx = _u32(data, off + chsize)
            name_idx = _u32(data, off + chsize + 4)
            attr_start = _u16(data, off + chsize + 8)
            attr_count = _u16(data, off + chsize + 12)
            attrs: dict[str, Any] = {}
            _ = ns_idx  # namespace index; resolved lazily from the string pool
            for i in range(attr_count):
                a = off + chsize + attr_start + i * 20
                a_ns = _u32(data, a)
                a_name = _u32(data, a + 4)
                raw = _u32(data, a + 8)
                dtype = data[a + 15]
                dval = _u32(data, a + 16)
                nm = pool.get(a_name)
                if not nm:
                    resid = res_map[a_name] if a_name < len(res_map) else 0
                    nm = ANDROID_ATTR_IDS.get(resid, f"0x{resid:08x}" if resid else "")
                if not nm:
                    continue
                prefix = "android" if (a_ns != 0xFFFFFFFF and pool.get(a_ns) == ANDROID_NS) else ""
                key = f"{prefix}:{nm}" if prefix else nm
                if dtype == TYPE_STRING:
                    val: Any = pool.get(dval) if raw == 0xFFFFFFFF else pool.get(dval)
                elif dtype == TYPE_INT_BOOLEAN:
                    val = bool(dval)
                elif dtype in (TYPE_INT_DEC, TYPE_INT_HEX):
                    val = dval
                elif dtype == TYPE_REFERENCE:
                    val = f"@0x{dval:08x}"
                elif dtype == TYPE_FLOAT:
                    val = struct.unpack("<f", struct.pack("<I", dval))[0]
                else:
                    val = pool.get(raw) if raw != 0xFFFFFFFF else dval
                attrs[key] = val
            node = {"tag": pool.get(name_idx) or "?", "attrs": attrs, "children": [], "parent": cur}
            cur["children"].append(node)
            cur = node
        elif ctype == RES_XML_END_ELEMENT:
            cur = cur.get("parent") or root
        off += csize
    return root


def manifest_from_plaintext(text: str) -> dict:
    """Parse a plaintext (debug-build) AndroidManifest.xml into the same tree shape."""
    import xml.etree.ElementTree as ET
    root_el = ET.fromstring(text)

    def conv(el, parent):
        attrs = {}
        for k, v in el.attrib.items():
            if k.startswith("{"):
                uri, local = k[1:].split("}", 1)
                attrs[f"android:{local}" if uri == ANDROID_NS else local] = v
            else:
                attrs[k] = v
        node = {"tag": el.tag if not el.tag.startswith("{") else el.tag.split("}", 1)[1],
                "attrs": attrs, "children": [], "parent": parent}
        for child in list(el):
            node["children"].append(conv(child, node))
        return node

    root = conv(root_el, None)
    # Match parse_axml's shape: a synthetic document node whose children start at
    # <manifest>, so build_manifest sees the same tree either way.
    return {"tag": "#document", "attrs": {}, "children": [root], "parent": None}


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        low = v.strip().lower()
        if low in ("true", "1"):
            return True
        if low in ("false", "0"):
            return False
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    return None


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip(), 0)
        except ValueError:
            return None
    return None


def build_manifest(tree: dict) -> dict:
    """Normalise a parsed manifest tree into the engine's manifest model."""
    man: dict[str, Any] = {
        "package": None, "versionCode": None, "versionName": None,
        "min_sdk": None, "target_sdk": None, "max_sdk": None,
        "permissions": [], "declared_permissions": [], "features": [],
        "application": {}, "components": [], "component_permissions": [],
        "deeplinks": [], "url_types": [], "tag_count": 0,
    }

    def walk(node: dict) -> None:
        tag = node["tag"]
        a = node["attrs"]
        man["tag_count"] += 1
        if tag == "manifest":
            man["package"] = a.get("package")
            man["versionCode"] = _as_int(a.get("android:versionCode"))
            man["versionName"] = a.get("android:versionName")
        elif tag == "uses-sdk":
            man["min_sdk"] = _as_int(a.get("android:minSdkVersion"))
            man["target_sdk"] = _as_int(a.get("android:targetSdkVersion"))
            man["max_sdk"] = _as_int(a.get("android:maxSdkVersion"))
        elif tag == "uses-permission" or tag == "uses-permission-sdk-23":
            nm = a.get("android:name")
            if nm and nm not in man["permissions"]:
                man["permissions"].append(nm)
        elif tag == "permission":
            nm = a.get("android:name")
            if nm:
                man["declared_permissions"].append(
                    {"name": nm, "protectionLevel": a.get("android:protectionLevel")})
        elif tag == "uses-feature":
            nm = a.get("android:name")
            if nm:
                man["features"].append(nm)
        elif tag == "application":
            man["application"] = {k.split(":", 1)[-1]: v for k, v in a.items()}
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            comp = {
                "kind": tag, "name": a.get("android:name"),
                "exported": _as_bool(a.get("android:exported")),
                "permission": a.get("android:permission"),
                "actions": [], "schemes": [], "hosts": [], "paths": [],
                "browsable": False, "authorities": a.get("android:authorities"),
                "process": a.get("android:process"),
            }
            for ch in node["children"]:
                if ch["tag"] == "intent-filter":
                    for g in ch["children"]:
                        ga = g["attrs"]
                        if g["tag"] == "action" and ga.get("android:name"):
                            comp["actions"].append(ga["android:name"])
                        elif g["tag"] == "data":
                            scheme = ga.get("android:scheme")
                            host = ga.get("android:host")
                            path = ga.get("android:path") or ga.get("android:pathPrefix") or ga.get("android:pathPattern")
                            if scheme:
                                comp["schemes"].append(scheme)
                                man["deeplinks"].append({
                                    "scheme": scheme, "host": host, "path": path,
                                    "component": comp["name"], "kind": tag,
                                    "browsable": False, "actions": comp["actions"]})
                            if host:
                                comp["hosts"].append(host)
                            if path:
                                comp["paths"].append(path)
                    if any(x == "android.intent.action.VIEW" for x in comp["actions"]) and \
                       any(x in ("android.intent.category.BROWSABLE",) for x in
                           [gg["attrs"].get("android:name") for gg in ch["children"] if gg["tag"] == "category"]):
                        comp["browsable"] = True
            if comp["name"]:
                man["components"].append(comp)
                if comp.get("permission"):
                    man["component_permissions"].append({"component": comp["name"],
                                                         "permission": comp["permission"]})
        for ch in node["children"]:
            walk(ch)

    for child in tree["children"]:
        walk(child)
    # propagate the browsable flag onto the deeplink records of each component
    browsable = {c["name"] for c in man["components"] if c["browsable"]}
    for d in man["deeplinks"]:
        d["browsable"] = d["component"] in browsable
    for comp in man["components"]:
        if comp["exported"] is None and comp["actions"]:
            comp["exported_note"] = ("not declared; platform default is exported=true because the component "
                                     "has an intent filter")
    return man


def summarise_manifest(man: dict | None) -> dict:
    if not man:
        return {}
    return {k: man.get(k) for k in ("package", "versionCode", "versionName", "min_sdk", "target_sdk",
                                    "permissions", "declared_permissions", "features", "application",
                                    "tag_count")} | {
        "component_count": len(man.get("components") or []),
        "exported_count": sum(1 for c in (man.get("components") or []) if c.get("exported") is True),
        "deeplink_count": len(man.get("deeplinks") or []),
    }


# ------------------------------------------------------------------ APK -----
def analyse_apk(path: str) -> dict:
    size = os.path.getsize(path)
    info: dict[str, Any] = {"kind": "apk", "path": path, "size": size, "sha256": sha256_file(path)}
    z = zipfile.ZipFile(path)
    names = z.namelist()
    info["entries"] = len(names)
    info["entries_sample"] = names[:40]
    info["dex_files"] = [n for n in names if n.endswith(".dex")]
    info["native_libs"] = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and "/" in n[5:]})
    info["resources_arsc"] = "resources.arsc" in names
    info["assets"] = [n for n in names if n.startswith("assets/")][:25]
    info["signing"] = detect_signing(path, names)
    info["dex"] = [dex_facts(z.read(n)) for n in info["dex_files"][:3]]
    man = None
    raw = None
    if "AndroidManifest.xml" in names:
        raw = z.read("AndroidManifest.xml")
        info["manifest_bytes"] = len(raw)
        info["manifest_format"] = "binary-axml" if raw[:2] == b"\x03\x00" else "plaintext-xml"
        try:
            if info["manifest_format"] == "binary-axml":
                tree = parse_axml(raw)
            else:
                tree = manifest_from_plaintext(raw.decode("utf-8", "replace"))
            man = build_manifest(tree)
            info["manifest_parse"] = "ok"
        except Exception as exc:
            info["manifest_parse"] = f"{type(exc).__name__}: {exc}"
    info["manifest"] = man
    return info


def dex_facts(blob: bytes) -> dict:
    if len(blob) < 0x70:
        return {"valid": False, "reason": "shorter than a dex header"}
    magic = blob[:8]
    if not magic.startswith(b"dex\n"):
        return {"valid": False, "reason": f"unexpected magic {magic!r}"}
    return {"valid": True, "version": magic[4:7].decode("ascii", "replace"),
            "file_size": _u32(blob, 32), "header_size": _u32(blob, 36),
            "string_ids": _u32(blob, 56), "method_ids": _u32(blob, 88)}


def detect_signing(path: str, names: list[str]) -> dict:
    """v1 (JAR) blocks from the archive, v2/v3 from the APK Signing Block magic."""
    v1 = [n for n in names if n.upper().startswith("META-INF/")
          and n.upper().endswith((".SF", ".RSA", ".DSA", ".EC"))]
    out = {"v1_files": v1, "v2_or_v3_block": False, "schemes": []}
    if v1:
        out["schemes"].append("v1")
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, os.path.getsize(path) - 262144))
            tail = fh.read()
        if b"APK Sig Block 42" in tail:
            out["v2_or_v3_block"] = True
            out["schemes"].append("v2+")
    except OSError as exc:
        out["error"] = str(exc)
    return out


# ------------------------------------------------------------------ IPA -----
def analyse_ipa(path: str) -> dict:
    info: dict[str, Any] = {"kind": "ipa", "path": path, "size": os.path.getsize(path),
                            "sha256": sha256_file(path), "manifest": None}
    z = zipfile.ZipFile(path)
    names = z.namelist()
    info["entries"] = len(names)
    apps = sorted({n.split("/")[1] for n in names
                   if n.startswith("Payload/") and n.count("/") >= 2 and n.split("/")[1].endswith(".app")})
    info["app_bundles"] = apps
    man: dict[str, Any] = {"package": None, "versionCode": None, "versionName": None,
                           "min_sdk": None, "target_sdk": None, "permissions": [], "features": [],
                           "declared_permissions": [], "components": [], "component_permissions": [],
                           "deeplinks": [], "url_types": [], "application": {}, "tag_count": 0}
    plist_data = None
    if apps:
        base = f"Payload/{apps[0]}/"
        if base + "Info.plist" in names:
            try:
                pl = plistlib.loads(z.read(base + "Info.plist"))
                plist_data = pl
                man["package"] = pl.get("CFBundleIdentifier")
                man["versionName"] = pl.get("CFBundleShortVersionString")
                man["versionCode"] = pl.get("CFBundleVersion")
                man["min_sdk"] = pl.get("MinimumOSVersion")
                man["target_sdk"] = pl.get("DTPlatformVersion") or pl.get("DTPlatformName")
                man["url_types"] = [{"name": u.get("CFBundleURLName"), "schemes": u.get("CFBundleURLSchemes") or []}
                                    for u in (pl.get("CFBundleURLTypes") or [])]
                man["deeplinks"] = [{"scheme": s, "host": None, "path": None, "component": u["name"],
                                     "kind": "url-scheme", "browsable": False}
                                    for u in man["url_types"] for s in u["schemes"]]
                man["permissions"] = plist_strings(pl, ("NSMicrophoneUsageDescription",
                                                        "NSCameraUsageDescription",
                                                        "NSLocationWhenInUseUsageDescription",
                                                        "NSLocationAlwaysAndWhenInUseUsageDescription",
                                                        "NSSpeechRecognitionUsageDescription",
                                                        "NSContactsUsageDescription",
                                                        "NSPhotoLibraryUsageDescription",
                                                        "NSBluetoothAlwaysUsageDescription",
                                                        "NSFaceIDUsageDescription",
                                                        "NSCalendarsUsageDescription",
                                                        "NSHealthShareUsageDescription",
                                                        "NSUserTrackingUsageDescription"))
                man["features"] = plist_strings(pl, ("UIRequiredDeviceCapabilities", "UIBackgroundModes"))
                ats = pl.get("NSAppTransportSecurity") or {}
                entitlements = pl.get("Entitlements") if isinstance(pl.get("Entitlements"), dict) else None
                man["application"] = {
                    "allowBackup": None,
                    "debuggable": bool(entitlements.get("get-task-allow")) if entitlements else None,
                    "usesCleartextTraffic": bool(ats.get("NSAllowsArbitraryLoads")) if ats else None,
                    "ATS": ats,
                    "UIFileSharingEnabled": pl.get("UIFileSharingEnabled"),
                    "LSApplicationQueriesSchemes": pl.get("LSApplicationQueriesSchemes"),
                }
                man["components"] = [{"kind": "url-scheme", "name": u["name"], "exported": True,
                                      "permission": None, "actions": u["schemes"], "schemes": u["schemes"]}
                                     for u in man["url_types"]]
                man["tag_count"] = len(pl)
                info["embedded_mobileprovision"] = (base + "embedded.mobileprovision") in names
            except Exception as exc:
                info["plist_parse"] = f"{type(exc).__name__}: {exc}"
        else:
            info["plist_parse"] = f"{base}Info.plist not present in the archive"
        frameworks = sorted({n.split("/")[3] for n in names
                             if n.startswith(base + "Frameworks/") and n.count("/") > 3})
        info["frameworks"] = frameworks
        exe = (plist_data or {}).get("CFBundleExecutable")
        bin_name = exe or apps[0][:-4]
        bpath = f"{base}{bin_name}"
        info["main_binary"] = bin_name
        if bpath in names:
            info["macho"] = macho_facts(z.read(bpath)[:4096])
    info["plist"] = {k: v for k, v in (plist_data or {}).items()
                     if k in ("CFBundleIdentifier", "CFBundleExecutable", "CFBundleShortVersionString",
                              "CFBundleVersion", "MinimumOSVersion", "UIDeviceFamily",
                              "NSAppTransportSecurity", "CFBundleURLTypes", "NSUserTrackingUsageDescription")}
    info["manifest"] = man
    return info


def plist_strings(pl: dict, keys: tuple[str, ...]) -> list[str]:
    return [k for k in keys if k in pl]


MACHO_MAGICS = {0xFEEDFACE: ("Mach-O 32-bit", "little"),
                0xCEFAEDFE: ("Mach-O 32-bit", "big"),
                0xFEEDFACF: ("Mach-O 64-bit", "little"),
                0xCFFAEDFE: ("Mach-O 64-bit", "big"),
                0xCAFEBABE: ("Mach-O universal (fat)", "big"),
                0xBEBAFECA: ("Mach-O universal (fat)", "little")}

CPU_TYPES = {7: "i386", 0x01000007: "x86_64", 12: "ARM", 0x0100000C: "ARM64", 18: "PowerPC"}
FILE_TYPES = {1: "object", 2: "executable", 6: "dylib", 8: "bundle"}
LC_ENCRYPTION_INFO_64 = 0x2C
LC_ENCRYPTION_INFO = 0x21
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25


def macho_facts(blob: bytes) -> dict:
    if len(blob) < 32:
        return {"valid": False, "reason": "shorter than a Mach-O header"}
    magic = struct.unpack_from(">I", blob, 0)[0] if blob[:4] in (b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xce",
                                                                b"\xfe\xed\xfa\xcf") else \
        struct.unpack_from("<I", blob, 0)[0]
    kind = MACHO_MAGICS.get(magic)
    if not kind:
        return {"valid": False, "reason": f"unrecognised magic 0x{magic:08x}"}
    endian = "<" if kind[1] == "little" else ">"
    out: dict[str, Any] = {"valid": True, "kind": kind[0], "endian": kind[1]}
    try:
        cputype, _sub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(f"{endian}iiIIII", blob, 4)
        out.update({"cpu": CPU_TYPES.get(cputype, f"0x{cputype:x}"), "filetype": FILE_TYPES.get(filetype, filetype),
                    "ncmds": ncmds, "flags": f"0x{flags:08x}",
                    "pie": bool(flags & 0x200000), "allow_stack_execution": bool(flags & 0x20000)})
        off = 32 if "64-bit" in kind[0] else 28
        for _ in range(min(ncmds, 64)):
            if off + 8 > len(blob):
                break
            cmd, cmdsize = struct.unpack_from(f"{endian}II", blob, off)
            if cmd in (LC_ENCRYPTION_INFO_64, LC_ENCRYPTION_INFO) and off + 20 <= len(blob):
                out["cryptid"] = struct.unpack_from(f"{endian}I", blob, off + 16)[0]
                out["encrypted"] = out["cryptid"] == 1
            elif cmd == LC_BUILD_VERSION and off + 12 <= len(blob):
                out["platform"] = {1: "macOS", 2: "iOS", 3: "tvOS", 6: "macCatalyst", 7: "iOSSimulator"}.get(
                    struct.unpack_from(f"{endian}I", blob, off + 8)[0])
            if cmdsize == 0:
                break
            off += cmdsize
    except struct.error as exc:
        out["parse_error"] = str(exc)
    return out


# ------------------------------------------------------- dependency parsing --
def parse_dependency_file(path: str) -> dict:
    name = os.path.basename(path).lower()
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        return {"format": "unreadable", "packages": [], "error": str(exc)}
    pkgs: list[dict] = []
    fmt = "unknown"
    if name.endswith(".json"):
        fmt = "package.json"
        try:
            doc = json.loads(text)
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                for k, v in (doc.get(section) or {}).items():
                    pkgs.append({"name": k, "version": str(v).lstrip("^~>=< "), "section": section})
        except json.JSONDecodeError as exc:
            return {"format": fmt, "packages": [], "error": str(exc)}
    elif "podfile.lock" in name:
        fmt = "Podfile.lock"
        for line in text.splitlines():
            m = re.match(r"^\s+-\s+(\S+)\s+\(([\d.]+)\)", line)
            if m:
                pkgs.append({"name": m.group(1), "version": m.group(2), "section": "pods"})
    elif name.endswith((".lock", ".lockfile")) or "gradle" in name:
        fmt = "gradle.lockfile/dependency-lock"
        for line in text.splitlines():
            m = re.match(r"^([\w.\-]+):([\w.\-]+):([\w.\-+]+)=", line.strip())
            if m:
                pkgs.append({"name": m.group(2), "version": m.group(3),
                             "group": m.group(1), "section": "gradle"})
    else:
        fmt = "requirements.txt/pip freeze"
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|~=)\s*([0-9][\w.\-]*)", line)
            if m:
                pkgs.append({"name": m.group(1), "version": m.group(2), "section": "python"})
    return {"format": fmt, "packages": pkgs}


def installed_python_dists() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for dist in importlib_metadata.distributions():
            nm = (dist.metadata or {}).get("Name")
            if nm:
                out[nm] = dist.version
    except Exception:
        return out
    return out


def version_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(v))
    return tuple(int(p) for p in parts[:4]) or (0,)


def match_known_vulns(packages: list[dict], origin: str = "") -> list[dict]:
    hits: list[dict] = []
    for pkg in packages:
        name = (pkg.get("name") or "").split("/")[-1].lower()
        ver = pkg.get("version") or ""
        if not name or not ver:
            continue
        vt = version_tuple(ver)
        for tbl_name, rng, advisory, sev, detail in KNOWN_VULN:
            if name != tbl_name.lower():
                continue
            try:
                limit = version_tuple(rng[1:])
            except Exception:
                continue
            op = rng[0]
            matched = vt < limit if op == "<" else False
            if matched:
                hits.append({"package": pkg.get("name"), "version": ver, "range": rng,
                             "advisory": advisory, "severity": sev, "detail": detail,
                             "origin": origin or pkg.get("section", ""),
                             "confidence": "candidate - verify upstream advisory"})
    return hits
