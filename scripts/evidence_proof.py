#!/usr/bin/env python3
"""Run one real assessment through the HTTP API and show its evidence trail.

Used to prove: files land in evidence_dir AND the SHA-256 that is logged is the
actual hash of those bytes.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.request



def _digest(path):
    """Same rule as engines.base.sha256_file: files by bytes, dirs by manifest."""
    import os
    if os.path.isdir(path):
        h = hashlib.sha256()
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, path).replace(os.sep, "/")
                h.update(rel.encode("utf-8")); h.update(b"\x00")
                h.update(_digest(full).encode("ascii")); h.update(b"\n")
        return h.hexdigest(), _size(path)
    h = hashlib.sha256(); n = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk); n += len(chunk)
    return h.hexdigest(), n


def _size(path):
    import os
    if os.path.isdir(path):
        return sum(os.path.getsize(os.path.join(r, f))
                   for r, _d, fs in os.walk(path) for f in fs)
    return os.path.getsize(path)

API = "http://127.0.0.1:8000"
C = json.load(open("/tmp/creds_ev.json"))


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            ctype = r.headers.get("content-type", "")
            return r.status, (json.loads(raw) if "json" in ctype else raw)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


code, r1 = call("POST", "/api/auth/stage1", {
    "username": C["user"], "password": C["pass"], "shortcut": C["shortcut"]})
print("stage1:", code)
if code != 200:
    print(r1)
    sys.exit(1)
tok = r1["token"]

code, r2 = call("POST", "/api/auth/stage2", {"pin": C["pin"]}, tok)
print("stage2:", code)
if code != 200:
    print(r2)
    sys.exit(1)

# The bootstrap password must be rotated before authorizing or executing tests.
# Do it explicitly so the script is idempotent (a 428 would stop the run later).
code, mp = call("GET", "/api/auth/me", token=tok)
if code == 200 and mp.get("user", {}).get("must_change_password"):
    new_pw = "Evidence-Proof-Pass-1"
    code, ch = call("POST", "/api/auth/password",
                    {"old_password": C["pass"], "new_password": new_pw}, tok)
    print("password rotation:", code)
    if code != 200:
        print(ch)
        sys.exit(1)
    C["pass"] = new_pw
    # Fresh session so the rotated credential is what the server validates.
    code, r1 = call("POST", "/api/auth/stage1", {
        "username": C["user"], "password": C["pass"], "shortcut": C["shortcut"]})
    if code != 200:
        print("re-login after rotation failed:", code, r1)
        sys.exit(1)
    tok = r1["token"]
    code, r2 = call("POST", "/api/auth/stage2", {"pin": C["pin"]}, tok)
    print("re-login stage2:", code)

call("POST", "/api/scope", {"target": "127.0.0.1", "description": "evidence proof"}, tok)
code, authz = call("POST", "/api/authorizations", {
    "targets": ["127.0.0.1"], "ttl_minutes": 20, "intended_test": "evidence proof"}, tok)
print("authorization:", code)

code, a = call("POST", "/api/assessments", {
    "template": "hardware_pentest", "targets": ["127.0.0.1"],
    "mode": "live", "intensity": "light"}, tok)
print("assessment:", code)
if code != 200:
    print(a)
    sys.exit(1)

code, run = call("POST", f"/api/assessments/{a['id']}/run",
                 {"authz_id": authz["id"], "confirm": True}, tok)
print("run:", code)
job = run["job_id"]
for _ in range(90):
    time.sleep(1)
    _, st = call("GET", f"/api/jobs/{job}", token=tok)
    if st["status"] in ("completed", "failed", "aborted"):
        print("job:", st["status"])
        break

code, detail = call("GET", f"/api/assessments/{a['id']}", token=tok)
print("assessment detail:", code)
arts = detail.get("artifacts") or []
print(f"artifacts recorded: {len(arts)}")

ok = 0
bad = 0
for art in arts:
    path = art.get("path")
    recorded = (art.get("sha256") or "")
    try:
        real, n = _digest(path)
        match = real == recorded
        size_ok = int(art.get("size") or 0) == n
        print(f"  {'MATCH' if match else 'MISMATCH':<9} {art['name']:<26} {n:>7}B  {real[:16]}...")
        if match and size_ok:
            ok += 1
        else:
            bad += 1
            if not match:
                print(f"            recorded={recorded}")
                print(f"            real    ={real}")
            if not size_ok:
                print(f"            size recorded={art.get('size')} real={n}")
    except OSError as e:
        bad += 1
        print(f"  MISSING   {art.get('name')}: {path} ({e})")

print()
print(f"RESULT: {ok} artifact(s) verified, {bad} problem(s)")
print("assessment id:", a["id"])
sys.exit(1 if bad or not arts else 0)
