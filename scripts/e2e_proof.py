#!/usr/bin/env python3
"""End-to-end proof over real HTTP against a running WD NEO instance.

Performs the full authorized workflow and prints every step's outcome:

    stage-1 (shortcut + password) -> stage-2 (PIN) -> scope -> authorization
    -> create assessment -> run -> poll job -> findings -> PDF report -> audit chain

Idempotent: it remembers a rotated bootstrap password, reuses an existing scope
entry, and tolerates an already-rotated password. Exit code 1 on any failure.

Usage:
    python3 scripts/e2e_proof.py <template> <target> [mode] [--api URL] [--creds PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def call(api: str, path: str, token: str | None = None, body: dict | None = None,
         method: str | None = None, timeout: int = 60):
    """Call the API and return (status, parsed-json-or-text)."""
    url = api.rstrip("/") + path
    data = None
    headers = {}
    if token:
        headers["authorization"] = "Bearer " + token
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method or ("POST" if data else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            raw = fh.read()
            ctype = fh.headers.get("content-type", "")
            status = fh.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        ctype = exc.headers.get("content-type", "")
        status = exc.code
    if "json" in ctype:
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError:
            return status, raw.decode("utf-8", "replace")
    return status, raw


def load_creds(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if ":" in line:
                key, _, value = line.partition(":")
                out[key.strip()] = value.strip()
    return {
        "user": out.get("Operator username", ""),
        "password": out.get("Operator password", ""),
        "pin": out.get("Stage-2 PIN", ""),
        "shortcut": out.get("Stage-1 WD shortcut", ""),
    }


def stage_one(api: str, creds: dict[str, str]) -> tuple[str | None, str]:
    """Authenticate stage 1, tolerating a previously rotated bootstrap password."""
    state = "/tmp/wd_e2e_password"
    candidates = []
    if os.path.exists(state):
        candidates.append(open(state, encoding="utf-8").read().strip())
    candidates.append(creds["password"])
    for password in candidates:
        status, body = call(api, "/api/auth/stage1", body={
            "username": creds["user"], "password": password,
            "shortcut": creds["shortcut"]})
        if status == 200 and isinstance(body, dict) and body.get("token"):
            return body["token"], password
    return None, creds["password"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("template")
    ap.add_argument("target")
    ap.add_argument("mode", nargs="?", default="live", choices=["live", "lab"])
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--creds", default=None)
    ap.add_argument("--params", default="{}")
    ap.add_argument("--timeout", type=int, default=240)
    args = ap.parse_args()

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    creds_path = args.creds or os.path.join(here, "database", "bootstrap_credentials.txt")
    creds = load_creds(creds_path)
    api = args.api

    # --- 1. stage 1 ---------------------------------------------------------
    token, password = stage_one(api, creds)
    if not token:
        print("FAIL stage-1")
        return 1
    print("ok   stage-1")

    # --- 2. stage 2 ---------------------------------------------------------
    status, body = call(api, "/api/auth/stage2", token=token, body={"pin": creds["pin"]})
    print(f"{'ok  ' if status == 200 else 'FAIL'} stage-2 ({status})")
    if status != 200:
        return 1

    # --- 3. rotate the bootstrap password once ------------------------------
    me_status, me = call(api, "/api/auth/me", token=token)
    must_change = bool(me_status == 200 and (me.get("user") or {}).get("must_change_password"))
    if must_change:
        newpass = "Rotated-" + creds["password"]
        st, _ = call(api, "/api/auth/password", token=token,
                     body={"old_password": password, "new_password": newpass})
        if st == 200:
            with open("/tmp/wd_e2e_password", "w", encoding="utf-8") as fh:
                fh.write(newpass)
            print("ok   password rotated (bootstrap requirement)")
        else:
            print(f"warn password rotation returned {st}")
    else:
        print("ok   password rotation not required")

    # --- 4. scope -----------------------------------------------------------
    st, _ = call(api, "/api/scope", token=token, body={"target": args.target})
    print(f"{'ok  ' if st in (200, 409) else 'FAIL'} scope ({st})")
    if st not in (200, 409):
        return 1

    # --- 5. authorization ---------------------------------------------------
    st, authz = call(api, "/api/authorizations", token=token, body={
        "targets": [args.target], "ttl_minutes": 30,
        "intended_test": "automated end-to-end proof"})
    if st != 200:
        print(f"FAIL authorization ({st}): {authz}")
        return 1
    authz_id = authz["id"]
    print(f"ok   authorization {authz_id[:8]}")

    # --- 6. create assessment ----------------------------------------------
    st, assessment = call(api, "/api/assessments", token=token, body={
        "template": args.template, "targets": [args.target], "mode": args.mode,
        "intensity": "light", "params": json.loads(args.params)})
    if st != 200:
        print(f"FAIL create assessment ({st}): {assessment}")
        return 1
    asid = assessment["id"]
    pre = assessment.get("preflight") or {}
    print(f"ok   assessment {asid[:8]} preflight={'pass' if pre.get('ok') else 'FAIL'}")
    if not pre.get("ok"):
        print(json.dumps(pre.get("checks"), indent=2))
        return 1

    # --- 7. run -------------------------------------------------------------
    st, job = call(api, f"/api/assessments/{asid}/run", token=token,
                   body={"authz_id": authz_id, "confirm": True})
    if st != 200:
        print(f"FAIL run ({st}): {job}")
        return 1
    job_id = job["job_id"]
    print(f"ok   job {job_id[:8]} queued")

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        time.sleep(2)
        st, state = call(api, f"/api/jobs/{job_id}", token=token)
        if st != 200:
            print(f"FAIL poll ({st})")
            return 1
        if state["status"] in ("completed", "failed", "aborted"):
            break
    else:
        print("FAIL job did not finish within timeout")
        return 1

    print(f"{'ok  ' if state['status'] == 'completed' else 'FAIL'} job {state['status']} "
          f"in {state.get('progress')}%")

    # --- 8. findings -------------------------------------------------------
    st, detail = call(api, f"/api/assessments/{asid}", token=token)
    if st != 200:
        print(f"FAIL fetch assessment ({st})")
        return 1
    summary = detail.get("summary") or {}
    findings = detail.get("findings") or []
    print(f"     status={detail['status']} risk={detail['risk_score']} "
          f"findings={len(findings)}")
    print(f"     by_status={summary.get('by_status')}")
    print(f"     by_source={summary.get('by_source')}")
    print(f"     artifacts={len(detail.get('artifacts') or [])}")
    print(f"  {'CHECK':11s} {'STATUS':11s} {'SEV':7s} {'SOURCE':11s} TITLE")
    for f in findings:
        print(f"  {f['check_id']:11s} {f.get('status', '?'):11s} {f['severity']:7s} "
              f"{f['evidence_source']:11s} {f['title'][:50]}")

    # contract assertions on live data
    problems = []
    for f in findings:
        if f["evidence_source"] == "unavailable" and f.get("status") != "unavailable":
            problems.append(f"{f['check_id']}: source=unavailable status={f.get('status')}")
        if f.get("status") == "unavailable" and f["evidence_source"] != "unavailable":
            problems.append(f"{f['check_id']}: status=unavailable source={f['evidence_source']}")
        if not f.get("status"):
            problems.append(f"{f['check_id']}: no status returned")
    if problems:
        print("FAIL persisted-status contract:")
        for p in problems:
            print("   ", p)
        return 1
    print("ok   persisted status/source contract holds on stored rows")

    # --- 9. report ---------------------------------------------------------
    st, pdf = call(api, f"/api/assessments/{asid}/report?fmt=pdf&lang=id",
                   token=token, timeout=120)
    magic = pdf[:5] if isinstance(pdf, bytes) else b""
    ok_pdf = st == 200 and magic == b"%PDF-"
    print(f"{'ok  ' if ok_pdf else 'FAIL'} report pdf ({status} {len(pdf) if isinstance(pdf, bytes) else 0} bytes)")
    if ok_pdf:
        out = os.path.join(here, "reports", f"e2e_{args.template}.pdf")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(pdf)
        print(f"     written to {out}")
    else:
        return 1

    # --- 10. audit chain ---------------------------------------------------
    st, verify = call(api, "/api/audit/verify", token=token)
    valid = st == 200 and verify.get("valid") is True
    print(f"{'ok  ' if valid else 'FAIL'} audit chain valid={verify.get('valid')} "
          f"events={verify.get('events')}")
    if not valid:
        return 1

    print(f"\nPASS  {args.template} / {args.target} / {args.mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
