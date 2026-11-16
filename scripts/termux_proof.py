#!/usr/bin/env python3
"""Prove the console works under a simulated Termux environment.

Termux has no iproute2, no venv, a different PREFIX and Android markers. This
script reproduces exactly those conditions (by hiding `ip` from PATH and setting
TERMUX_* variables) and then asserts the whole stack still works:

  1. platform detection reports termux
  2. interfaces() still returns real rows via the fallback chain
  3. /api/network advertises a usable on-device URL
  4. the API boots, logs in (2 stages) and runs an assessment end-to-end

Run:  python3 scripts/termux_proof.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0


def check(condition: bool, label: str, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [ ok ] {label}" + (f"  ({detail})" if detail else ""))
    else:
        FAIL += 1
        print(f"  [FAIL] {label}" + (f"  ({detail})" if detail else ""))


print("=" * 70)
print("Termux environment simulation")
print("=" * 70)

# --- Build a PATH with no `ip`, no `ss`, no `ifconfig` -----------------------
tmp_bin = Path(tempfile.mkdtemp(prefix="termux_bin_"))
for tool in ("python3", "bash", "sh", "env"):
    real = shutil.which(tool)
    if real:
        (tmp_bin / tool).symlink_to(real)

os.environ["PATH"] = str(tmp_bin)
os.environ["TERMUX_VERSION"] = "0.118.3"
os.environ["PREFIX"] = "/data/data/com.termux/files/usr"
os.environ["HOME"] = "/data/data/com.termux/files/home"

# Isolated storage so the proof cannot touch the real database.
work = Path(tempfile.mkdtemp(prefix="termux_proof_"))
os.environ["WD_DATA_DIR"] = str(work / "database")
os.environ["WD_EVIDENCE_DIR"] = str(work / "evidence")
os.environ["WD_REPORT_DIR"] = str(work / "reports")
os.environ["WD_DATABASE_URL"] = f"sqlite:///{work / 'database' / 'proof.db'}"

print(f"PATH      : {tmp_bin}")
print(f"ip on PATH: {shutil.which('ip')}")
print(f"storage   : {work}")
print()

# --- 1. platform detection ---------------------------------------------------
print("1. platform detection")
from backend import platform_utils as P  # noqa: E402

check(P.is_termux() is True, "is_termux() true under TERMUX_VERSION")
check(P.is_android() is True, "is_android() true")
check(P.platform_label() == "termux", "platform_label is termux", P.platform_label())
check(P.has_iproute2() is False, "iproute2 reported absent")
print()

# --- 2. interface fallback ---------------------------------------------------
print("2. interface detection without iproute2")
rows = P.interfaces()
check(isinstance(rows, list) and len(rows) > 0, "interfaces() returns rows", f"{len(rows)} row(s)")
for r in rows:
    print(f"        {r['name']:<10} {r['state']:<5} {r['addresses']}")
names = {r["name"] for r in rows}
check("lo" in names, "loopback present")
check(P.interface_source() in ("psutil", "ioctl"), "fallback path used", P.interface_source())
lan = P.primary_lan_ip()
check(lan is None or not lan.startswith("127."), "primary LAN IP is not loopback", str(lan))
print()

# --- 3. discovered URLs ------------------------------------------------------
print("3. reachable URLs")
urls = P.lan_urls(8000)
check(urls[0] == "http://127.0.0.1:8000", "on-device URL first", urls[0])
check(all(u.startswith("http://") for u in urls), "all URLs are http")
info = P.network_info(8000)
check(info["platform"] == "termux", "/api/network would report termux")
check(info["on_device_url"].startswith("http://127.0.0.1:"), "on_device_url is loopback")
print()

# --- 4. full API boot + login + assessment ----------------------------------
print("4. API boot, two-stage login, real assessment")
from fastapi.testclient import TestClient  # noqa: E402

os.environ["WD_ADMIN_USER"] = "WD-TERMUX-OP"
os.environ["WD_ADMIN_PASSWORD"] = "Termux-Proof-Pass-1"
os.environ["WD_ADMIN_PIN"] = "13572468"
os.environ["WD_SHORTCUT"] = "WD-TERMUXPROOF01"
os.environ["WD_FORCE_PASSWORD_CHANGE"] = "0"

from backend import capabilities, config, database  # noqa: E402
config.reload()
config.ensure_dirs()
database.init_db()

from backend.main import app  # noqa: E402

with TestClient(app) as client:
    health = client.get("/api/health")
    check(health.status_code == 200, "GET /api/health", str(health.status_code))
    engines = health.json().get("engines", {})
    check(len(engines.get("registered", [])) >= 7, "engines registered",
          f"{len(engines.get('registered', []))}")

    net = client.get("/api/network")
    check(net.status_code == 200, "GET /api/network (public)", str(net.status_code))
    payload = net.json()
    check(payload["is_termux"] is True, "network payload says termux")
    check(payload["has_iproute2"] is False, "network payload: no iproute2")
    check(payload["interface_source"] in ("psutil", "ioctl"), "network payload: fallback",
          payload["interface_source"])

    caps = client.get("/api/capabilities")
    check(caps.status_code == 200, "GET /api/capabilities")
    check(caps.json()["platform"] == "termux", "capabilities platform termux")
    check(len(caps.json()["interfaces"]) > 0, "capabilities lists interfaces")

    r1 = client.post("/api/auth/stage1", json={
        "username": "WD-TERMUX-OP", "password": "Termux-Proof-Pass-1",
        "shortcut": "WD-TERMUXPROOF01"})
    check(r1.status_code == 200, "stage 1 login", r1.text[:80])
    token = r1.json().get("token", "")
    h = {"authorization": f"Bearer {token}"}

    r2 = client.post("/api/auth/stage2", json={"pin": "13572468"}, headers=h)
    check(r2.status_code == 200 and r2.json().get("stage") == 2, "stage 2 PIN", r2.text[:80])

    client.post("/api/scope", json={"target": "127.0.0.1", "description": "termux proof"}, headers=h)
    authz = client.post("/api/authorizations", json={
        "targets": ["127.0.0.1"], "ttl_minutes": 15, "intended_test": "termux proof"},
        headers=h)
    check(authz.status_code == 200, "authorization issued", str(authz.status_code))

    created = client.post("/api/assessments", json={
        "template": "hardware_pentest", "targets": ["127.0.0.1"],
        "mode": "live", "intensity": "light"}, headers=h)
    check(created.status_code == 200, "assessment created", created.text[:80])
    asid = created.json()["id"]

    run = client.post(f"/api/assessments/{asid}/run", json={
        "authz_id": authz.json()["id"], "confirm": True}, headers=h)
    check(run.status_code == 200, "assessment started", run.text[:80])

    job = run.json()["job_id"]
    final = None
    for _ in range(60):
        time.sleep(1)
        st = client.get(f"/api/jobs/{job}", headers=h).json()
        if st["status"] in ("completed", "failed", "aborted"):
            final = st
            break
    check(final is not None and final["status"] == "completed",
          "assessment completed", (final or {}).get("status", "timeout"))

    findings = client.get(f"/api/assessments/{asid}/findings", headers=h)
    check(findings.status_code == 200 and len(findings.json()["findings"]) > 0,
          "findings recorded", f"{len(findings.json().get('findings', []))}")

    audit = client.get("/api/audit/verify", headers=h)
    check(audit.status_code == 200 and audit.json()["valid"] is True, "audit chain valid")

    pdf = client.get(f"/api/assessments/{asid}/report?fmt=pdf&lang=id", headers=h)
    check(pdf.status_code == 200 and pdf.content[:4] == b"%PDF", "PDF report (Indonesian)",
          f"{len(pdf.content)} bytes")

print()
print("=" * 70)
print(f"RESULT: {PASS} passed, {FAIL} failed")
print("=" * 70)
sys.exit(1 if FAIL else 0)
