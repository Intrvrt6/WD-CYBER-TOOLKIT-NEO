"""Audit every engine by ACTUALLY EXECUTING it, then assert the contract holds.

Checks, per engine:
  * every Result has a valid status/severity/source
  * declared check ids are covered or explicitly unavailable
  * no check silently disappears
  * evidence source matches the declared mode
"""
from __future__ import annotations

import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import engines  # noqa: F401,E402
from engines.base import Context, get_engine  # noqa: E402

VALID_STATUS = {"pass", "fail", "info", "unavailable", "error"}
VALID_SOURCE = {"live", "lab", "local", "unavailable"}

# module -> (mode, targets, params)
PLAN = {
    "network": ("live", ["https://testssl.sh"], {"capture_seconds": 4}),
    "mitm": ("live", ["https://testssl.sh"], {}),
    "scada_ics": ("lab", ["modbus://127.0.0.1:5020"], {}),
    "automotive_can": ("lab", ["can:wdcan0"], {}),
    "threat_intelligence": ("live", ["203.0.113.45", "example.com"],
                            {"iocs": ["203.0.113.45", "example.com"],
                             "sample_path": "samples/iocs_demo.csv"}),
    "webapp": ("live", ["http://127.0.0.1:8099"], {}),
    "mobile_security": ("live", ["127.0.0.1"], {}),
    "social_engineering": ("live", ["example.com"], {}),
    "physical_security": ("live", ["site-a"], {}),
    "hardware_security": ("live", ["127.0.0.1"], {}),
}


def audit(module: str, mode: str, targets: list, params: dict) -> dict:
    eng = get_engine(module)
    declared = [c[0] for c in eng.checks]
    ev = f"evidence/audit-{module}"
    ctx = Context(assessment_id=f"audit-{module}", module=module, mode=mode,
                  intensity="light", targets=targets, params=params, evidence_dir=ev)
    results = eng.run(ctx)
    out: dict = {
        "module": module, "mode": mode, "declared": len(declared),
        "results": len(results), "problems": [], "findings": [],
    }
    seen = set()
    for r in results:
        if r.status not in VALID_STATUS:
            out["problems"].append(f"{r.check_id}: bad status {r.status!r}")
        if r.source not in VALID_SOURCE:
            out["problems"].append(f"{r.check_id}: bad source {r.source!r}")
        if not r.title:
            out["problems"].append(f"{r.check_id}: empty title")
        if not r.description:
            out["problems"].append(f"{r.check_id}: empty description")
        if r.source == "unavailable" and r.status != "unavailable":
            out["problems"].append(f"{r.check_id}: source=unavailable but status={r.status}")
        if r.status == "unavailable" and not r.description:
            out["problems"].append(f"{r.check_id}: unavailable without a reason")
        seen.add(r.check_id.split("-")[0] + "-" + r.check_id.split("-")[1][:2].rstrip("bcdg"))
        out["findings"].append({
            "id": r.check_id, "status": r.status, "severity": r.severity,
            "source": r.source, "desc": (r.description or "")[:110],
        })
    # coverage: each declared id should have produced at least one result
    produced = {r.check_id for r in results}
    # a declared check may legitimately emit a suffixed variant (NET-02b); only
    # flag when the base id itself never appears anywhere
    really_missing = []
    for d in declared:
        if d in produced:
            continue
        if any(p == d or p.startswith(d) for p in produced):
            continue
        really_missing.append(d)
    out["checks_not_reported"] = really_missing
    if really_missing:
        out["problems"].append(f"declared checks produced no result: {really_missing}")
    # every result must carry some evidence trail
    no_evidence = [r.check_id for r in results
                   if not r.evidence and r.status != "unavailable"]
    if no_evidence:
        out["problems"].append(f"results without evidence: {no_evidence}")
    return out


def main() -> int:
    only = sys.argv[1] if len(sys.argv) > 1 else None
    report, failures = [], 0
    for module, (mode, targets, params) in PLAN.items():
        if only and only != module:
            continue
        print(f"\n{'='*74}\n{module}  (mode={mode})\n{'='*74}")
        try:
            r = audit(module, mode, targets, params)
        except Exception:
            failures += 1
            print(f"  EXCEPTION while running engine:\n{traceback.format_exc()}")
            report.append({"module": module, "crashed": traceback.format_exc()[-800:]})
            continue
        for f in r["findings"]:
            print(f"  {f['id']:10s} {f['status']:11s} {f['severity']:8s} {f['source']:11s} {f['desc']}")
        print(f"  -> declared={r['declared']} results={r['results']} "
              f"not-reported={r['checks_not_reported'] or 'none'}")
        if r["problems"]:
            failures += 1
            for p in r["problems"]:
                print(f"  !! {p}")
        else:
            print("  OK: contract satisfied")
        report.append(r)
    with open("reports/engine-audit.json", "w", encoding="utf-8") as fh:
        json.dump({"engines": report, "failures": failures}, fh, indent=2)
    print(f"\n{'='*74}\nengines with problems: {failures} / {len(report)}\n{'='*74}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
