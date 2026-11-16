"""Audit every engine's emitted Results against the platform's result invariants.

Run: python3 tests/audit_all_engines.py

Invariants checked
  1. status is one of pass|fail|info|unavailable|error
  2. severity is one of critical|high|medium|low|info
  3. source is one of live|lab|local|unavailable
  4. status="unavailable"  <=>  source="unavailable"   (a gap must say it is a gap)
  5. status="info" implies severity="info"            (info is not a severity-bearing failure)
  6. status="fail" implies severity != "info"         (a failure has a severity)
  7. every result carries a non-empty description
  8. every result carries a non-empty check_id
  9. check_id matches the engine's declared check ids (or a documented sub-id X-NNn)
"""
from __future__ import annotations

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engines import base  # noqa: E402
from engines.base import Context  # noqa: E402
import engines  # noqa: F401,E402

STATUSES = {"pass", "fail", "info", "unavailable", "error"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
SOURCES = {"live", "lab", "local", "unavailable"}

# (module, targets, params, mode)
PLAN = [
    ("network", ["127.0.0.1"], {"capture_seconds": 3}, "lab"),
    ("mitm", ["https://testssl.sh"], {}, "live"),
    ("scada_ics", ["modbus://127.0.0.1:5020"], {}, "lab"),
    ("automotive_can", ["can:wdcan0"], {}, "lab"),
    ("threat_intelligence", ["203.0.113.45"], {"iocs": ["203.0.113.45", "example.com"],
                                                "sample_path": "samples/iocs_demo.csv"}, "live"),
    ("webapp", ["http://127.0.0.1:8099"], {}, "live"),
    ("mobile_security", ["127.0.0.1"], {}, "live"),
    ("social_engineering", ["example.com"], {}, "live"),
    ("physical_security", ["site-a"], {}, "live"),
    ("hardware_security", ["127.0.0.1"], {}, "live"),
]


def valid_subid(check_id: str, declared: list[str]) -> bool:
    """X-01b and X-01-c style sub-ids are legitimate; they must share a declared stem."""
    if check_id in declared:
        return True
    for d in declared:
        if check_id.startswith(d):
            rest = check_id[len(d):]
            if rest and rest[0].isalpha() or rest.startswith("-"):
                return True
    return False


def main() -> int:
    failures: list[str] = []
    total = 0

    for module, targets, params, mode in PLAN:
        if module not in base.modules():
            failures.append(f"{module}: ENGINE NOT REGISTERED")
            continue
        eng = base.get_engine(module)
        declared = [c[0] for c in eng.checks]
        ctx = Context(
            assessment_id=f"audit-{module}", module=module, mode=mode,
            intensity="light", targets=targets, params=params,
            evidence_dir=os.path.join("/tmp", "wd-audit", module),
        )
        try:
            results = eng.run(ctx)
        except Exception:
            failures.append(f"{module}: run() raised:\n{traceback.format_exc()}")
            continue

        if not results:
            failures.append(f"{module}: emitted zero results")
            continue

        reported = {r.check_id for r in results}
        missing = [c for c in declared if not any(cid == c or cid.startswith(c) for cid in reported)]
        if missing:
            failures.append(f"{module}: declared checks with no result: {missing}")

        for r in results:
            total += 1
            where = f"{module}/{r.check_id}"
            if r.status not in STATUSES:
                failures.append(f"{where}: bad status {r.status!r}")
            if r.severity not in SEVERITIES:
                failures.append(f"{where}: bad severity {r.severity!r}")
            if r.source not in SOURCES:
                failures.append(f"{where}: bad source {r.source!r}")
            if (r.status == "unavailable") != (r.source == "unavailable"):
                failures.append(f"{where}: status={r.status} but source={r.source}")
            if r.status == "info" and r.severity != "info":
                failures.append(f"{where}: status=info but severity={r.severity}")
            if r.status == "fail" and r.severity == "info":
                failures.append(f"{where}: status=fail but severity=info")
            if not (r.description or "").strip():
                failures.append(f"{where}: empty description")
            if not valid_subid(r.check_id, declared):
                failures.append(f"{where}: check_id not declared/derived")

    print(f"results audited: {total}")
    if failures:
        print(f"PROBLEMS: {len(failures)}")
        for f in failures:
            print("  -", f)
        return 1
    print("all invariants hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
