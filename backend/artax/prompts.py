"""Artax system prompt and evidence-grounded context builders.

Artax is deliberately constrained: it may only reason about evidence the
platform actually produced. It is told to say "not observed" rather than
invent, mirroring the engine contract.
"""
from __future__ import annotations

from typing import Any

SYSTEM_PROMPT = """You are Artax, the analyst assistant inside WD CYBER TOOLKIT NEO - a
professional, authorized penetration-testing platform.

Hard rules:
1. Reason ONLY from the evidence supplied in the context block. Never invent a
   finding, host, port, CVE, version or command output.
2. Every finding carries an evidence source: "live" (real target/interface),
   "lab" (bundled simulator), "local" (this host), "unavailable" (check could
   not run). Treat "lab" as simulator evidence and say so. Treat "unavailable"
   as a coverage gap, NEVER as a pass.
3. If the context does not answer the question, say what is missing and which
   module or parameter would obtain it. "Not observed" is a valid answer.
4. Be concrete: cite check IDs, assets, severities and CVSS where present.
5. Answer in the language the operator used (Indonesian or English).
6. You are advisory only: you cannot execute commands, change scope, or
   authorize testing. Recommend, do not claim you performed anything.

Useful frames when relevant: OWASP WSTG/ASVS, PTES, NIST SP 800-115,
MITRE ATT&CK (and ATT&CK for ICS), IEC 62443, ISO/SAE 21434, CVSS, CWE.
Be concise and use short headings or bullets."""


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _finding_line(f: dict[str, Any]) -> str:
    bits = [f"[{f.get('check_id') or '?'}]", f"{f.get('severity', 'info')}",
            f"src={f.get('evidence_source', '?')}", f"{f.get('title')}"]
    if f.get("asset"):
        bits.append(f"asset={f['asset']}")
    if f.get("cvss_score") is not None:
        bits.append(f"cvss={f['cvss_score']}")
    if f.get("cwe"):
        bits.append("cwe=" + ",".join(f["cwe"]))
    return " | ".join(str(b) for b in bits)


def build_assessment_context(assessment: dict[str, Any], findings: list[dict[str, Any]],
                             max_findings: int = 40, artifacts: list[dict] | None = None) -> str:
    """Compact, deterministic evidence block for the model."""
    s = assessment.get("summary") or {}
    lines = [
        "=== ASSESSMENT ===",
        f"name: {assessment.get('name')}",
        f"id: {assessment.get('id')}",
        f"template: {assessment.get('template')}",
        f"module: {assessment.get('module')}",
        f"mode: {assessment.get('mode')}",
        f"intensity: {assessment.get('intensity')}",
        f"status: {assessment.get('status')}",
        f"risk_score: {assessment.get('risk_score')}",
        f"targets: {', '.join(assessment.get('targets') or []) or 'none'}",
        f"operator: {assessment.get('operator')}",
        f"checks_expected: {', '.join(s.get('checks_expected') or []) or 'n/a'}",
        f"checks_reported: {', '.join(s.get('checks_reported') or []) or 'n/a'}",
        f"by_severity: {s.get('by_severity') or {}}",
        f"by_source: {s.get('by_source') or {}}",
        f"unavailable_checks: {s.get('unavailable')}",
    ]
    exp = set(s.get("checks_expected") or [])
    got = set(s.get("checks_reported") or [])
    missing = sorted(exp - got)
    if missing:
        lines.append(f"CHECKS THAT DID NOT REPORT: {', '.join(missing)}")

    if artifacts:
        lines.append("=== EVIDENCE ARTIFACTS ===")
        for a in artifacts[:15]:
            lines.append(f"- {a.get('name')} ({a.get('kind')}, {a.get('size')} B, sha256={str(a.get('sha256'))[:16]}...)")

    lines.append("=== FINDINGS (severity ordered) ===")
    if not findings:
        lines.append("(no findings recorded)")
    else:
        def rank(f):
            sev = f.get("severity", "info")
            return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99
        for f in sorted(findings, key=rank)[:max_findings]:
            lines.append(_finding_line(f))
            desc = (f.get("description") or "").strip().replace("\n", " ")
            if desc:
                lines.append(f"    detail: {desc[:400]}")
            if f.get("remediation"):
                lines.append(f"    remediation: {str(f['remediation'])[:300]}")
        if len(findings) > max_findings:
            lines.append(f"... ({len(findings) - max_findings} more findings omitted)")
    return "\n".join(lines)


def build_platform_context(health: dict, modules: dict, caps: dict) -> str:
    eng = (health or {}).get("engines") or {}
    cli = {k: v for k, v in ((caps or {}).get("cli_tools") or {}).items() if v.get("present")}
    missing = [k for k, v in ((caps or {}).get("cli_tools") or {}).items() if not v.get("present")]
    lines = [
        "=== PLATFORM ===",
        f"instance: {health.get('instance')} v{health.get('version')}",
        f"engines registered: {', '.join(sorted(eng.get('registered') or [])) or 'none'}",
        f"engines unavailable: {', '.join(sorted((eng.get('failed') or {}).keys())) or 'none'}",
        f"emergency_stop: {((health.get('emergency_stop') or {}).get('active'))}",
        f"cli tools present: {', '.join(sorted(cli)) or 'none'}",
        f"cli tools missing: {', '.join(sorted(missing)) or 'none'}",
    ]
    mods = (modules or {}).get("modules") or []
    if mods:
        lines.append("modules: " + "; ".join(f"{m.get('module')}({len(m.get('checks') or [])} checks)" for m in mods))
    return "\n".join(lines)
